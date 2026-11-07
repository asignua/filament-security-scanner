<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Scanners;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Models\SecurityBaselineEntry;
use Asignua\FilamentSecurityScanner\Scanning\BaselineSnapshot;
use Asignua\FilamentSecurityScanner\Scanning\Contracts\Scanner;
use Asignua\FilamentSecurityScanner\Scanning\Evidence;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\GitStatus;
use Asignua\FilamentSecurityScanner\Scanning\PathNormalizer;
use Asignua\FilamentSecurityScanner\Scanning\Rule;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Scanning\Zone;
use Generator;

/**
 * Code integrity: two INDEPENDENT sources, each covering the blind spot of the other.
 *
 * GIT is responsible for tracked files. Its strength is that the reference is the remote
 * commit, which the attacker does not control: he cannot replace both the file AND the reference at once.
 * Its blindness is ignored paths, and that is exactly where web shells were found on 2026-09-20.
 *
 * The HASH SNAPSHOT is responsible for what git does not see: `vendor/` (16k files
 * under .gitignore, rebuilt on every deploy) and any zone added by the host. Its
 * weakness is the mirror image: the snapshot gets POISONED if tampering happened before it was taken.
 *
 * Hence both, not one. And hence the snapshot is a deploy step, not a schedule item.
 *
 * No rule of this scanner is ever deterministic: auto-quarantining a hotfix
 * placed by hand would destroy trust faster than any intrusion.
 */
final class CodeIntegrityScanner implements Scanner
{
    private const array EXECUTABLE_EXTENSIONS = [
        'php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
        'phtml', 'pht', 'phar', 'phps', 'inc', 'shtml', 'cgi', 'pl', 'py', 'sh',
    ];

    /** @var list<string> */
    private array $issues = [];

    public function id(): string
    {
        return 'code';
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
        yield from $this->fromGit($context);

        foreach ($context->zones as $zone) {
            if ($zone->kind === SecurityZoneKind::Vendor) {
                yield from $this->fromBaseline($zone, $context);
            }
        }
    }

    /**
     * @return Generator<Finding>
     */
    private function fromGit(ScanContext $context): Generator
    {
        $git = new GitStatus($context->base);

        if (!$git->available()) {
            $this->issues = array_merge($this->issues, $git->issues());
            // Tracked files were not checked: old git findings have not "disappeared".
            $context->issues?->markIncomplete($this->id());

            yield $this->make($context, 'code.git-unavailable', '', [
                'reason' => 'git checkout unavailable; integrity of tracked files was NOT checked',
            ]);

            return;
        }

        $entries = $git->entries();

        if ($entries === null) {
            $this->issues = array_merge($this->issues, $git->issues());
            $context->issues?->markIncomplete($this->id());

            yield $this->make($context, 'code.git-unavailable', '', [
                'reason' => 'git status did not answer; integrity of tracked files was NOT checked',
            ]);

            return;
        }

        foreach ($entries as $entry) {
            $path = $entry['path'];

            if ($context->isAllowlisted($path) || !$context->covers($path)) {
                continue;
            }

            $ruleId = $this->ruleForStatus($entry['status'], $path);

            if ($ruleId === null) {
                continue;
            }

            // A modified or untracked file in the repository is a candidate for
            // content reading: this is exactly what substitution of tracked code looks like.
            if (!str_contains($entry['status'], 'D')) {
                $context->candidates?->add($path, $this->id());
            }

            yield $this->make($context, $ruleId, $path, array_filter([
                'git_status' => trim($entry['status']),
                'renamed_from' => $entry['from'],
            ], static fn (mixed $v): bool => $v !== null && $v !== ''));
        }

        yield from $this->headMoved($git, $context);
        yield from $this->hiddenFromGit($git, $context);

        $this->issues = array_merge($this->issues, $git->issues());
    }

    /**
     * A commit makes `git status` clean, so a HEAD that differs from the one
     * recorded with the baseline is a finding of its own. It stays open until
     * `security:baseline` is run again, which is why the deploy must run it.
     *
     * @return Generator<Finding>
     */
    private function headMoved(GitStatus $git, ScanContext $context): Generator
    {
        $recorded = BaselineSnapshot::recordedHead();

        if ($recorded === null) {
            return;
        }

        $current = $git->head(full: true);

        if ($current === null) {
            $context->issues?->markIncomplete($this->id());

            return;
        }

        if ($current !== $recorded) {
            yield $this->make($context, 'code.git-head-moved', 'HEAD', [
                'recorded' => substr($recorded, 0, 12),
                'current' => substr($current, 0, 12),
                'hint' => 'run security:baseline as part of the deploy',
            ]);
        }
    }

    /**
     * What `git status` cannot show: ignored PHP files inside code directories, and
     * index flags (assume-unchanged / skip-worktree) that make a modified file look
     * clean. Each of them is a place to hide a shell in tracked code.
     *
     * @return Generator<Finding>
     */
    private function hiddenFromGit(GitStatus $git, ScanContext $context): Generator
    {
        /** @var list<string> $dirs */
        $dirs = array_values(array_filter(
            (array) config('security-scanner.git.ignored_php_paths', ['app', 'bootstrap', 'config', 'database', 'resources', 'routes']),
            static fn (mixed $v): bool => is_string($v) && $v !== '',
        ));

        $ignored = $git->ignoredPhpFiles($dirs);

        if ($ignored === null) {
            $context->issues?->markIncomplete($this->id());
        }

        foreach ($ignored ?? [] as $path) {
            // The compiled-cache directory is ignored by design.
            if (str_starts_with($path, 'bootstrap/cache/')
                || $context->isAllowlisted($path)
                || !$context->covers($path)) {
                continue;
            }

            $context->candidates?->add($path, $this->id());

            yield $this->make($context, 'code.ignored-php-file', $path, ['reason' => 'ignored by .gitignore; git status does not list it']);
        }

        $flags = $git->hiddenIndexEntries();

        if ($flags === null) {
            $context->issues?->markIncomplete($this->id());
        }

        foreach ($flags ?? [] as $entry) {
            if ($context->isAllowlisted($entry['path']) || !$context->covers($entry['path'])) {
                continue;
            }

            $context->candidates?->add($entry['path'], $this->id());

            yield $this->make($context, 'code.git-index-flag', $entry['path'], ['flag' => $entry['flag']]);
        }

        foreach ($git->executableConfig() as $key) {
            $this->issues[] = sprintf('git config "%s" makes git run a command; review .git/config', $key);

            yield $this->make($context, 'code.git-executable-config', '.git/config#'.$key, ['key' => $key]);
        }
    }

    /**
     * Status of `git status --porcelain` → rule.
     *
     * Untracked files are separated ON PURPOSE: an untracked `.php` in the repository
     * is high, while an untracked README is low. If everything untracked lit up as
     * high, a developer's working tree would produce dozens of findings, and the list
     * would stop being read by the second day.
     */
    private function ruleForStatus(string $status, string $path): ?string
    {
        $flags = str_replace(' ', '', $status);

        if ($flags === '??') {
            return array_intersect(PathNormalizer::extensionChain($path), self::EXECUTABLE_EXTENSIONS) !== []
                ? 'code.untracked-executable'
                : 'code.untracked-file';
        }

        return match (true) {
            str_contains($flags, 'R'), str_contains($flags, 'C') => 'code.renamed-file',
            // Staged addition: not in HEAD yet, so it is as foreign as an untracked file.
            str_contains($flags, 'A') => array_intersect(PathNormalizer::extensionChain($path), self::EXECUTABLE_EXTENSIONS) !== []
                ? 'code.untracked-executable'
                : 'code.untracked-file',
            // Unmerged paths (UU, AA, DU…).
            str_contains($flags, 'U') => 'code.modified-file',
            str_contains($flags, 'D') => 'code.deleted-file',
            str_contains($flags, 'M'), str_contains($flags, 'T') => 'code.modified-file',
            default => null,
        };
    }

    /**
     * @return Generator<Finding>
     */
    private function fromBaseline(Zone $zone, ScanContext $context): Generator
    {
        $snapshot = BaselineSnapshot::latestComplete($zone->name);

        if ($snapshot === null) {
            // A mass "everything is new" alarm never happens: without a snapshot we simply
            // skip the zone, but loudly.
            yield $this->make($context, 'code.baseline-missing', $zone->name, [
                'zone' => $zone->name,
                'hint' => 'take it: security:baseline --zone='.$zone->name,
            ], $zone);

            return;
        }

        /** @var array<string, string> $stored */
        $stored = SecurityBaselineEntry::query()
            ->where('snapshot_id', $snapshot)
            ->pluck('content_hash', 'path')
            // PostgreSQL pads `char(n)` with spaces on read; a hash never contains blanks.
            ->map(static fn (mixed $hash): string => rtrim((string) $hash))
            ->all();

        $algo = (string) (SecurityBaselineEntry::query()
            ->where('snapshot_id', $snapshot)
            ->value('hash_algo') ?? BaselineSnapshot::algo());

        foreach (BaselineSnapshot::walk($zone, $context, $this->id()) as $file) {
            $relative = PathNormalizer::relative($file->getPathname(), $context->base);

            if ($context->isAllowlisted($relative)) {
                continue;
            }

            $hash = @hash_file($algo, $file->getPathname());

            if ($hash === false) {
                continue;
            }

            if (!array_key_exists($relative, $stored)) {
                yield $this->make($context, 'code.baseline-added', $relative, ['zone' => $zone->name], $zone);

                continue;
            }

            if (!hash_equals($stored[$relative], $hash)) {
                yield $this->make($context, 'code.baseline-modified', $relative, ['zone' => $zone->name], $zone);
            }

            unset($stored[$relative]);
        }

        foreach (array_keys($stored) as $missing) {
            // Asymmetry between the walk and the leftovers: the loop above skips a path that
            // is covered by the SCAN allowlist, and therefore NEVER does
            // `unset($stored[...])` for it. Without this check such a path would stay in
            // $stored forever and be reported every night as "deleted", although it
            // simply was not supposed to be scanned (a real case: the BASELINE allowlist
            // does not exclude `vendor/asignua/filament-security-scanner/tests/fixtures/**`,
            // while the SCAN one does).
            if ($context->isAllowlisted($missing) || !$context->covers($missing)) {
                continue;
            }

            yield $this->make($context, 'code.baseline-removed', $missing, ['zone' => $zone->name], $zone);
        }
    }

    /**
     * @param array<string, scalar|null> $detail
     */
    private function make(ScanContext $context, string $ruleId, string $path, array $detail = [], ?Zone $zone = null): Finding
    {
        $rule = $context->rules->get($ruleId);

        // The rule may have been disabled or removed from the registry: the finding does not
        // disappear because of that, it only loses its signature and severity tuning. Medium as the fallback
        // level was chosen deliberately: it neither mutes nor screams.
        $severity = $rule instanceof Rule ? $rule->severity : SecuritySeverity::Medium;

        return new Finding(
            ruleId: $ruleId,
            scanner: $this->id(),
            severity: $severity,
            title: $rule instanceof Rule ? $rule->message : $ruleId,
            path: $path,
            evidence: [Evidence::plain($ruleId, $path, $detail)],
            zone: $zone?->name,
            zoneKind: $zone?->kind,
            disk: $zone?->disk,
            deterministic: false,
            registrySource: $rule?->source,
            registryVersion: $rule?->version,
        );
    }
}
