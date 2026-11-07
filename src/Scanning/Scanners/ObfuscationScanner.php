<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Scanners;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Scanning\BaselineSnapshot;
use Asignua\FilamentSecurityScanner\Scanning\Contracts\Scanner;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;
use Asignua\FilamentSecurityScanner\Scanning\PathNormalizer;
use Asignua\FilamentSecurityScanner\Scanning\Rule;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Scanning\Zone;
use Generator;
use SplFileInfo;
use Throwable;

/**
 * Obfuscation: the only scanner that reads file CONTENT, on suspicion.
 *
 * Who gets read is decided by {@see ScanContext::shouldInspectContent()}:
 * candidates from previous scanners (suspicious extension, change in git) and
 * files modified since the previous full run. The first run reads everything:
 * a one-time cost per site lifetime.
 *
 * Why not "candidates only", as the spec originally had it: a polyglot with an innocent
 * extension (`baal.jpg` from the incident) will never become a candidate; it is
 * caught precisely by the mtime gate. And why not "everything every night": 69,565 media disk files,
 * 159 seconds, measured.
 *
 * No rule here is deterministic: the registry validator guarantees this, not an
 * agreement. A regex will not get the right to move someone else's file.
 */
final class ObfuscationScanner implements Scanner
{
    /** @var list<string> */
    private array $issues = [];

    public function id(): string
    {
        return 'obfuscation';
    }

    public function enabled(): bool
    {
        return (bool) config('security-scanner.enabled', false);
    }

    /**
     * @return list<string>
     */
    public function issues(): array
    {
        return $this->issues;
    }

    /**
     * @return Generator<Finding>
     */
    public function scan(ScanContext $context): Generator
    {
        $visited = [];

        foreach ($context->zones as $zone) {
            // vendor is covered by the hash snapshot; regexes over it are guaranteed false
            // positives (nikic/php-parser legitimately prints __halt_compiler).
            if ($zone->kind === SecurityZoneKind::Vendor) {
                continue;
            }

            if ($this->rulesForKind($context, $zone->kind) === []) {
                continue;
            }

            foreach ($this->candidates($zone, $context) as $file) {
                if ($context->outOfTime()) {
                    $this->issues[] = sprintf('time budget exhausted in zone "%s"', $zone->name);

                    return;
                }

                $relative = PathNormalizer::relative($file->getPathname(), $context->base);
                $visited[$relative] = true;

                yield from $this->inspect($context, $relative, $file->getPathname(), $zone, (int) @$file->getMTime(), (int) @$file->getSize(), (int) @$file->getCTime());
            }
        }

        // Candidates outside zones: primarily modified tracked files from git
        // (app/, routes/…): they are in no zone, because tracked code is covered by
        // git, but their CONTENT after a change is worth reading.
        foreach ($context->candidates?->all() ?? [] as $relative) {
            if (isset($visited[$relative])) {
                continue;
            }

            $absolute = rtrim($context->base, '/').'/'.$relative;

            if (!is_file($absolute) || is_link($absolute)) {
                continue;
            }

            yield from $this->inspect($context, $relative, $absolute, null, (int) @filemtime($absolute), (int) @filesize($absolute), (int) @filectime($absolute));
        }
    }

    /**
     * Source of zone candidates: a full walk, or, when the run is narrowed to
     * specific paths (reaction to an upload, A10), one
     * `file_exists()`/`is_link()` per given path. The same motive as in
     * UploadZoneScanner::candidates(): a targeted run must not be allowed to
     * walk the whole zone.
     *
     * Symlinks from both branches are dropped IDENTICALLY: `BaselineSnapshot::walk()`
     * (full walk) always skips them (`isDir() || isLink()`), while
     * `Zone::restrictedCandidates()`, on the contrary, DELIBERATELY returns them (so that
     * UploadZoneScanner sees them). Without this filter a narrowed run here
     * would read the content of a LIVE symlink (fopen() follows the link), which
     * a full run never does: a symbolic link remains the area of
     * responsibility of UploadZoneScanner, obfuscation does not follow it.
     *
     * @return Generator<SplFileInfo>
     */
    private function candidates(Zone $zone, ScanContext $context): Generator
    {
        if ($context->restrictToPaths === []) {
            yield from BaselineSnapshot::walk($zone);

            return;
        }

        foreach ($zone->restrictedCandidates($context->restrictToPaths, $context->base) as $file) {
            if ($file->isLink()) {
                continue;
            }

            yield $file;
        }
    }

    /**
     * @return Generator<Finding>
     */
    private function inspect(ScanContext $context, string $relative, string $absolute, ?Zone $zone, int $mtime, int $size, int $ctime): Generator
    {
        if ($context->isAllowlisted($relative) || !$context->covers($relative)) {
            return;
        }

        $context->filesSeen?->add($relative);

        if (!$context->shouldInspectContent($relative, $mtime, $this->id(), $ctime)) {
            return;
        }

        // A candidate outside zones (a modified tracked file from git) is code.
        $kind = $zone instanceof Zone ? $zone->kind : SecurityZoneKind::Code;
        $subject = MatchSubject::make($absolute, $kind, $context->base, $size);
        $rules = $context->rules->covering($subject, $this->id());

        if ($rules === []) {
            return;
        }

        if ($size > $context->maxFileSize) {
            // Silence is not the same as clean.
            yield $this->oversized($context, $relative, $zone, $size);

            return;
        }

        $budget = max(1, $context->rules->readBudget($subject, $this->id()));
        $bytes = $this->read($absolute, $budget, $relative);

        if ($bytes === null) {
            return;
        }

        $subject = new MatchSubject(
            path: $subject->path,
            basename: $subject->basename,
            extensionChain: $subject->extensionChain,
            zoneKind: $kind,
            size: $size,
            bytes: $bytes,
        );
        $contentHash = hash('sha256', $bytes);

        foreach ($rules as $rule) {
            // `covering()` above filtered only by PATH; allowlist.hashes
            // from the rule registry sees concrete content only here, after the file is
            // read: computing sha256 a second time for each rule makes no sense.
            if ($rule->isAllowlisted($subject->path, $contentHash)) {
                continue;
            }

            $evidence = $rule->evaluate($subject);

            if ($evidence === []) {
                continue;
            }

            yield new Finding(
                ruleId: $rule->id,
                scanner: $this->id(),
                severity: $rule->severity,
                title: $rule->message,
                path: $relative,
                evidence: $evidence,
                zone: $zone?->name,
                zoneKind: $kind,
                disk: $zone?->disk,
                deterministic: false,
                size: $size,
                mtime: $mtime,
                contentHash: $contentHash,
                registrySource: $rule->source,
                registryVersion: $rule->version,
            );
        }
    }

    private function read(string $absolute, int $budget, string $relative): ?string
    {
        try {
            $handle = @fopen($absolute, 'rb');

            if ($handle === false) {
                $this->issues[] = sprintf('file cannot be opened: %s', $relative);

                return null;
            }

            $bytes = (string) fread($handle, max(1, $budget));
            fclose($handle);

            return $bytes;
        } catch (Throwable $e) {
            $this->issues[] = sprintf('read error %s: %s', $relative, $e->getMessage());

            return null;
        }
    }

    private function oversized(ScanContext $context, string $relative, ?Zone $zone, int $size): Finding
    {
        $rule = $context->rules->get('obf.oversized-unreadable');

        return new Finding(
            ruleId: 'obf.oversized-unreadable',
            scanner: $this->id(),
            severity: $rule instanceof Rule ? $rule->severity : SecuritySeverity::Info,
            title: $rule instanceof Rule ? $rule->message : 'obf.oversized-unreadable',
            path: $relative,
            zone: $zone?->name,
            zoneKind: $zone?->kind,
            disk: $zone?->disk,
            size: $size,
        );
    }

    /**
     * @return list<Rule>
     */
    private function rulesForKind(ScanContext $context, SecurityZoneKind $kind): array
    {
        return array_values(array_filter(
            $context->rules->forZone($kind),
            fn (Rule $r): bool => $r->scanner === $this->id(),
        ));
    }
}
