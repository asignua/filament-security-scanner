<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityScanStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityScanTrigger;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Events\SecurityScanFinished;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Scanning\Contracts\Scanner;
use Asignua\FilamentSecurityScanner\Scanning\Scanners\CodeIntegrityScanner;
use Asignua\FilamentSecurityScanner\Scanning\Scanners\EnvironmentHygieneScanner;
use Asignua\FilamentSecurityScanner\Scanning\Scanners\ObfuscationScanner;
use Asignua\FilamentSecurityScanner\Scanning\Scanners\UploadZoneScanner;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Throwable;

/**
 * Runs the scanners and stores the result in the database.
 *
 * All database work is concentrated here on purpose: the scanners stay pure
 * functions and are tested without a DB, while dedup, statuses and closing have
 * exactly one place where they could drift apart.
 *
 * SCANNER ORDER is not cosmetic: `uploads` and `code` build the candidate set,
 * while `obfuscation` takes it from the context and does not walk the file
 * system at all. `hygiene` goes last and must run even when everything before it
 * failed, because the "scanner degraded" signal lives there.
 */
final class ScanRunner
{
    /**
     * @param list<Scanner> $scanners
     */
    public function __construct(private readonly array $scanners) {}

    /**
     * The default scanner set for a FULL pass, in a FIXED order. ONE place for
     * the console command (`security:scan`) and the "Tools" button
     * ({@see \Asignua\FilamentSecurityScanner\Jobs\SecurityScanJob}); without it the
     * list would inevitably drift apart: a change would land only in the
     * command, and a manual run from the panel would silently use a stale
     * scanner set.
     *
     * @return list<Scanner>
     */
    public static function defaultScanners(): array
    {
        return [
            new CodeIntegrityScanner,
            new UploadZoneScanner,
            new ObfuscationScanner,
            new EnvironmentHygieneScanner,
        ];
    }

    /**
     * @param list<string> $restrictToPaths
     */
    public function run(
        SecurityScanTrigger $trigger = SecurityScanTrigger::Manual,
        array $restrictToPaths = [],
        ?int $timeBudgetSeconds = null,
        bool $rereadContent = false,
    ): SecurityScan {
        $startedAt = now();

        // The row is written AT START. A run killed by OOM or a timeout must
        // leave a trace: a scanner that silently did not run looks exactly like
        // "all clean".
        $scan = new SecurityScan;
        $scan->ulid = (string) Str::ulid();
        $scan->trigger = $trigger;
        $scan->status = SecurityScanStatus::Running;
        $scan->started_at = $startedAt;
        $scan->save();

        $rules = RuleRegistry::load(fresh: true);
        [$zones, $zoneIssues] = Zones::resolve();

        // The mtime gate boundary is PER SCANNER: the last full run (ok/findings,
        // not partial, since that one did not look everywhere) in which this
        // scanner took part. A scanner added later than the rest would otherwise
        // consider old files already checked.
        $previousRunsByScanner = [];

        foreach ($this->scanners as $scanner) {
            // ->first(), NOT ->value('started_at'): value() returns the raw DB
            // string bypassing the model casts, so instanceof Carbon would always
            // be false, the map empty and the gate disabled. That means the whole
            // disk would be read every night, and the run would not show it: it
            // is merely slower.
            $previous = SecurityScan::query()
                ->whereNot('id', $scan->id)
                ->whereIn('status', [SecurityScanStatus::Ok->value, SecurityScanStatus::Findings->value])
                ->whereJsonContains('scanners->ran', $scanner->id())
                ->orderByDesc('id')
                ->first(['id', 'started_at']);

            if ($previous instanceof SecurityScan && $previous->started_at instanceof Carbon) {
                $previousRunsByScanner[$scanner->id()] = $previous->started_at;
            }
        }

        $context = new ScanContext(
            base: Zones::base(),
            zones: $zones,
            rules: $rules,
            allowlist: self::allowlist(),
            restrictToPaths: array_map(
                static fn (string $p): string => PathNormalizer::relative($p),
                $restrictToPaths,
            ),
            deadlineAt: $timeBudgetSeconds !== null ? $startedAt->copy()->addSeconds($timeBudgetSeconds) : null,
            // "First" = there was no COMPLETED full run before it (ok/findings;
            // a partial, targeted or aborted run does not count, the same
            // predicate as in the mtime gate). Plain "there are no other rows"
            // broke on a single upload check or a run killed by OOM: the next
            // full run became "not the first", and auto-quarantine moved legacy
            // files before a human had looked even once.
            isFirstRun: !SecurityScan::query()
                ->whereNot('id', $scan->id)
                ->whereIn('status', [SecurityScanStatus::Ok->value, SecurityScanStatus::Findings->value])
                ->exists(),
            maxFileSize: (int) config('security-scanner.max_file_size', 33554432),
            previousRunsByScanner: $previousRunsByScanner,
            forceContentRead: $rereadContent,
            candidates: new CandidateSet,
            issues: new ScanIssues,
            filesSeen: new FilesSeen,
        );

        $issues = array_merge($rules->issues, $zoneIssues);
        $context->issues?->addMany('zones', $zoneIssues);
        $ran = [];
        $seen = [];
        $new = 0;
        $total = 0;
        $files = 0;
        $quarantined = 0;
        $degraded = false;

        foreach ($this->scanners as $scanner) {
            if (!$scanner->enabled()) {
                continue;
            }

            $ran[] = $scanner->id();

            try {
                foreach ($scanner->scan($context) as $finding) {
                    $total++;
                    $fingerprint = $finding->fingerprint();

                    if (isset($seen[$fingerprint])) {
                        continue;
                    }

                    $seen[$fingerprint] = true;

                    // Storing ONE finding has its own try: an exception here used to
                    // escape into the outer catch and end the whole scanner, so every
                    // file after the "bad" one was left unvisited. The run becomes
                    // `partial` meanwhile: a finding was lost, and it has no right to
                    // close old ones as gone.
                    try {
                        [$model, $isNew] = $this->persist($finding, $scan, $rules->version);
                    } catch (Throwable $e) {
                        $degraded = true;
                        $message = sprintf('failed to store finding %s (%s): %s', PathNormalizer::storable($finding->path), $finding->ruleId, $e->getMessage());
                        $issues[] = $message;
                        $context->issues?->add($scanner->id(), $message);

                        continue;
                    }

                    $new += $isNew ? 1 : 0;

                    // The ONLY place where the machine moves a file. All eight
                    // conditions are in Quarantine::mayAutoQuarantine(); this is just
                    // the call. A row whose path had to be escaped or truncated no
                    // longer points to the disk: move() would look for a file that
                    // does not exist.
                    $rule = $rules->get($finding->ruleId);

                    if ($isNew
                        && $rule instanceof Rule
                        && $model->path === $finding->path
                        && Quarantine::mayAutoQuarantine($finding, $rule, $context, rtrim($context->base, '/').'/'.$finding->path)) {
                        try {
                            Quarantine::move($model, auto: true);
                            $quarantined++;
                        } catch (Throwable $e) {
                            $issues[] = sprintf('quarantine %s: %s', $finding->path, $e->getMessage());
                        }
                    }
                }
            } catch (Throwable $e) {
                // One scanner failing does not take the others' results with it, but
                // it is not hidden either: the run becomes `partial`, and a partial
                // run does not close findings.
                $degraded = true;
                $issues[] = sprintf('scanner "%s" crashed: %s', $scanner->id(), $e->getMessage());
                $context->issues?->add($scanner->id(), 'crashed: '.$e->getMessage());
            }

            $issues = array_merge($issues, $scanner->issues());
            $context->issues?->addMany($scanner->id(), $scanner->issues());
        }

        $issues = array_merge($issues, $context->issues?->unreadable() ?? []);

        $partial = $degraded || $context->outOfTime() || $restrictToPaths !== [];

        $status = match (true) {
            $partial => SecurityScanStatus::Partial,
            $new > 0 || $total > 0 => SecurityScanStatus::Findings,
            default => SecurityScanStatus::Ok,
        };

        // PROTECTIVE INVARIANT: a run that did not cover the zones fully HAS NO
        // RIGHT to move old findings to `resolved`. Otherwise a timeout or a
        // targeted run triggered by an upload would silently close a real
        // intrusion.
        $resolved = 0;

        // A scanner that ran INCOMPLETELY (git did not answer) takes no part in
        // closing: its silence means "not checked", not "gone". And the next
        // run's mtime gate must not treat such a pass as complete, so only the
        // complete ones stay in `ran`.
        $incomplete = $context->issues?->incomplete() ?? [];
        $complete = array_values(array_diff($ran, $incomplete));

        if ($status->closesFindings()) {
            $seen = $this->reverifyUnseen($seen, $scan, $rules, $context->base, $complete);
            $resolved = $this->closeUnseen(array_keys($seen), $scan, $complete);
        }

        $scan->status = $status;
        $scan->scanners = [
            // Issue texts carry file system paths; without escaping, broken UTF-8
            // would fail saving the run itself, and the row would stay `running`.
            'issues' => array_map(
                static fn (string $issue): string => PathNormalizer::escapeBytes($issue),
                $issues,
            ),
            'resolved' => $resolved,
            'first_run' => $context->isFirstRun,
            'zones' => array_map(static fn (Zone $z): string => $z->name, $zones),
            'candidates' => $context->candidates?->count() ?? 0,
            // How many DISTINCT files the run actually inspected: proof that a
            // narrowed pass (reaction to an upload, A10) does not walk the whole
            // zone, only the given paths.
            'files_seen' => $context->filesSeen?->count() ?? 0,
            'quarantined' => $quarantined,
            'ran' => $complete,
            'incomplete' => $incomplete,
        ];
        $scan->registry_version = $rules->version;
        $scan->files_scanned = $files;
        $scan->findings_new = $new;
        $scan->findings_total = count($seen);
        $scan->finished_at = now();
        $scan->duration_ms = (int) $startedAt->diffInMilliseconds(now());
        $scan->save();

        // The event is only a "take a look" signal. The listener re-reads "new
        // and not yet notified" findings from the DB itself, so nothing is lost
        // even if two runs finish back to back or the listener fails on the
        // first one.
        $top = SecurityFinding::query()->open()->orderByDesc('severity_weight')->value('severity');

        SecurityScanFinished::dispatch(
            $scan->ulid,
            $new,
            count($seen),
            is_string($top) ? $top : null,
            $context->isFirstRun,
        );

        return $scan;
    }

    /**
     * @return list<string>
     */
    public static function allowlist(): array
    {
        /** @var list<mixed> $list */
        $list = (array) config('security-scanner.allowlist.scan', []);

        return array_values(array_filter($list, static fn (mixed $v): bool => is_string($v) && $v !== ''));
    }

    /**
     * @return array{0: SecurityFinding, 1: bool} the model and whether the finding is NEW
     */
    private function persist(Finding $finding, SecurityScan $scan, string $registryVersion): array
    {
        $fingerprint = $finding->fingerprint();
        $existing = SecurityFinding::query()->where('fingerprint', $fingerprint)->first();

        if ($existing instanceof SecurityFinding) {
            $existing->times_seen = $existing->times_seen + 1;
            $existing->last_seen_at = now();
            $existing->last_scan_id = $scan->id;

            // A finding that was once closed as gone OR moved to quarantine, while
            // the file reappeared at the same path, is a NEW event and must not be
            // silent. "Quarantined" is a badge about the FORMER copy; the file on
            // disk now is no longer it, and mayAutoQuarantine() does not see it at
            // all while isNew stays false. A human decision (`ignored`,
            // `acknowledged`) is respected: that is what it was made for.
            // `quarantine_path`/`quarantined_at`/`quarantine_auto` are deliberately
            // NOT touched: they are the trace of the previous copy, and thanks to
            // them a later restore() correctly refuses: the path is occupied by a
            // new file.
            $cameBack = in_array($existing->status, [
                SecurityFindingStatus::Resolved,
                SecurityFindingStatus::Quarantined,
            ], true);

            if ($cameBack) {
                $existing->status = SecurityFindingStatus::New;
                $existing->notified_channels = null;
                $existing->notified_at = null;
            }

            $existing->save();

            return [$existing, $cameBack];
        }

        $model = new SecurityFinding;
        $model->ulid = (string) Str::ulid();
        $model->fingerprint = $fingerprint;
        $model->first_scan_id = $scan->id;
        $model->last_scan_id = $scan->id;
        $model->scanner = $finding->scanner;
        $model->rule_id = $finding->ruleId;
        $model->severity = $finding->severity;
        $model->severity_weight = $finding->severity->weight();
        $model->zone = $finding->zone;
        $model->zone_kind = $finding->zoneKind;
        $model->disk = $finding->disk;
        $model->path = PathNormalizer::storable($finding->path);
        $model->title = $finding->title;
        $model->evidence = $finding->evidenceArray();
        $model->size = $finding->size;
        $model->file_mtime = $finding->mtime;
        $model->content_hash = $finding->contentHash;
        // The first run gives NO leniency to the status: the three files of the
        // incident had to light up on exactly that run. The leniency is only in
        // presentation: the notification knows about isFirstRun and words the
        // mail as an inventory, not as the day's events.
        $model->status = SecurityFindingStatus::New;
        $model->times_seen = 1;
        $model->first_seen_at = now();
        $model->last_seen_at = now();
        $model->registry_source = $finding->registrySource;
        $model->registry_version = $finding->registryVersion ?? $registryVersion;
        $model->save();

        return [$model, true];
    }

    /**
     * UNREAD != GONE.
     *
     * The mtime gate deliberately does not re-read old unchanged files, so the
     * obfuscation scanner does not "see" them although they have not gone
     * anywhere. Without this check closeUnseen() would close them as gone, and
     * that is exactly how a polyglot JPEG dropped out of the list on a live
     * tree on the very first run after the gate was introduced.
     *
     * For every unseen open finding with a content hash we re-read the file
     * with the same budget: same hash means the finding is alive and is merely
     * touched; the file is gone or changed means we leave closeUnseen() to close
     * it (a changed file has a new mtime, so it was already re-inspected and a
     * new finding, if any, is created separately).
     *
     * @param array<string, true> $seen
     * @param list<string>        $ran
     *
     * @return array<string, true>
     */
    private function reverifyUnseen(array $seen, SecurityScan $scan, RuleSet $rules, string $base, array $ran): array
    {
        if ($ran === []) {
            return $seen;
        }

        // Resolved ones too: a file restored from a backup with an OLD mtime is
        // never re-read by the gate, while its finding is already resolved.
        // Re-checking returns it to new, just as persist() does for a file that
        // reappeared and is picked up for reading. Ignored (`ignored`) ones are
        // not touched: that is a human decision.
        $query = SecurityFinding::query()
            ->whereIn('scanner', $ran)
            ->whereNotNull('content_hash')
            ->whereIn('status', [
                SecurityFindingStatus::New->value,
                SecurityFindingStatus::Acknowledged->value,
                SecurityFindingStatus::Resolved->value,
            ]);

        if ($seen !== []) {
            $query->whereNotIn('fingerprint', array_keys($seen));
        }

        foreach ($query->get() as $finding) {
            // The rule must STILL belong to the scanner on whose behalf the finding
            // was recorded. A rule that moved between scanners or disappeared from
            // the registry leaves an orphaned finding; closeUnseen() must close
            // it, not the hash check keep it alive. On a live tree exactly such
            // orphans from the first, still faulty run doubled the list.
            $rule = $rules->get($finding->rule_id);

            if (!$rule instanceof Rule || $rule->scanner !== $finding->scanner) {
                continue;
            }

            // An escaped or truncated path does not open a file, so there is
            // nothing to check it with. "Cannot verify" != "gone": we keep the
            // finding alive so that a shell with a broken name does not close
            // itself on the first run where the mtime gate did not re-read it.
            if (PathNormalizer::wasAltered((string) $finding->path)) {
                $seen[$finding->fingerprint] = true;

                continue;
            }

            $absolute = rtrim($base, '/').'/'.(string) $finding->path;

            if (!is_file($absolute) || is_link($absolute)) {
                continue;
            }

            // INVARIANT: the verification hash must be computed over the SAME
            // prefix the scanner hashed: the MAXIMUM `max_read_bytes` across ALL
            // rules covering the file, not THIS rule's own budget. For a rule with
            // a smaller limit than its neighbours in the same scanner
            // (obf.php-after-binary: 64 KB vs the typical 1 MB) the hash here would
            // otherwise always differ on a file larger than 64 KB, and a live file
            // would go to closeUnseen() as gone.
            $zoneKind = $finding->zone_kind instanceof SecurityZoneKind
                ? $finding->zone_kind
                : SecurityZoneKind::Code;
            $subject = MatchSubject::make($absolute, $zoneKind, $base, (int) @filesize($absolute));
            $budget = max(1, $rules->readBudget($subject, $finding->scanner));
            $handle = @fopen($absolute, 'rb');

            if ($handle === false) {
                continue;
            }

            $bytes = (string) fread($handle, $budget);
            fclose($handle);

            if (!hash_equals(rtrim((string) $finding->content_hash), hash('sha256', $bytes))) {
                continue;
            }

            $finding->times_seen = $finding->times_seen + 1;
            $finding->last_seen_at = now();
            $finding->last_scan_id = $scan->id;

            if ($finding->status === SecurityFindingStatus::Resolved) {
                $finding->status = SecurityFindingStatus::New;
                $finding->notified_channels = null;
                $finding->notified_at = null;
                $finding->status_note = null;
            }

            $finding->save();

            $seen[$finding->fingerprint] = true;
        }

        return $seen;
    }

    /**
     * Closes findings that the pass no longer saw.
     *
     * Limited to scanners that actually ran THIS TIME. Otherwise a disabled (or
     * not yet wired) scanner would silently declare its findings gone: measured
     * on a live tree, a real JPEG polyglot went to `resolved` exactly because
     * the obfuscation scanner did not take part in that run. The threat had not
     * gone anywhere.
     *
     * @param list<string> $seenFingerprints
     * @param list<string> $ranScanners
     */
    private function closeUnseen(array $seenFingerprints, SecurityScan $scan, array $ranScanners): int
    {
        if ($ranScanners === []) {
            return 0;
        }

        $query = SecurityFinding::query()
            ->whereIn('scanner', $ranScanners)
            ->whereIn('status', [
                SecurityFindingStatus::New->value,
                SecurityFindingStatus::Acknowledged->value,
            ]);

        if ($seenFingerprints !== []) {
            $query->whereNotIn('fingerprint', $seenFingerprints);
        }

        return $query->update([
            'status' => SecurityFindingStatus::Resolved->value,
            'status_changed_at' => now(),
            'status_note' => __('security-scanner::ui.Condition no longer present'),
            'last_scan_id' => $scan->id,
        ]);
    }
}
