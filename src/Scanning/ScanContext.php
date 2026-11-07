<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Illuminate\Support\Carbon;

/**
 * Everything a scanner needs to know about the current run.
 *
 * `deadlineAt` is not cosmetic: a production media disk is 69k files and 2 GB,
 * and a pass must be able to honestly say "ran out of time" instead of hanging.
 * A run that hits the deadline gets the `partial` status, and that one HAS NO
 * RIGHT to close old findings as gone; otherwise a timeout would silently hide a
 * real intrusion.
 *
 * `restrictToPaths` narrows the pass to specific files; this is how the reaction
 * to uploads works: the same scanner, the same logic, one target.
 */
final readonly class ScanContext
{
    /**
     * @param list<Zone>   $zones
     * @param list<string> $restrictToPaths relative paths; empty = the whole zone
     * @param list<string> $allowlist       glob patterns excluded from scanning
     */
    public function __construct(
        public string $base,
        public array $zones,
        public RuleSet $rules,
        public array $allowlist = [],
        public array $restrictToPaths = [],
        public ?Carbon $deadlineAt = null,
        public bool $isFirstRun = false,
        public int $maxFileSize = 33554432,
        /** @var array<string, Carbon> $previousRunsByScanner the last FULL run in which the scanner took part */
        public array $previousRunsByScanner = [],
        public bool $forceContentRead = false,
        public ?CandidateSet $candidates = null,
        public ?ScanIssues $issues = null,
        public ?FilesSeen $filesSeen = null,
    ) {}

    /**
     * Whether the CONTENT of this file is worth reading on this run.
     *
     * Three grounds, each sufficient: another scanner has already pointed at the
     * file; THIS scanner has never completed a full pass yet (there is no
     * baseline, so we read everything, once); or the file was changed after the
     * last full run in which this scanner TOOK PART. The mtime gate is what keeps
     * the nightly cost at "what changed today", not "the whole disk every night".
     *
     * The gate is PER SCANNER, and this is not pedantry: a scanner added later
     * than the rest would otherwise consider all old files "already checked", and
     * that is exactly how a polyglot with a June mtime would slip past a freshly
     * added obfuscation scanner.
     *
     * The gate looks at the GREATER of mtime and ctime. mtime is set by the
     * attacker (`touch -d 2025-01-01` is a standard trick for a shell), and a
     * polyglot with a forged mtime in an upload zone would never be read. ctime
     * cannot be forged from user code: the kernel bumps it on any inode change,
     * including `touch` itself. The cost is a one-off re-read of everything after
     * `chown -R` or a restore from backup.
     *
     * What the gate does NOT catch is an added ZONE: the scanner has already
     * "completed a pass" there, so old files of the new zone would never be read
     * until someone changes them. That is what `forceContentRead` is for
     * (`security:scan --reread`): one forced pass after a deploy that brings a
     * zone. It must not be put on the schedule: that is the whole disk every
     * night.
     */
    public function shouldInspectContent(string $relativePath, ?int $mtime, string $scanner, ?int $ctime = null): bool
    {
        if ($this->forceContentRead) {
            return true;
        }

        if ($this->candidates instanceof CandidateSet && $this->candidates->has($relativePath)) {
            return true;
        }

        $previous = $this->previousRunsByScanner[$scanner] ?? null;

        if (!$previous instanceof Carbon) {
            return true;
        }

        if ($mtime === null) {
            return true;
        }

        return max($mtime, $ctime ?? 0) >= $previous->getTimestamp();
    }

    public function outOfTime(): bool
    {
        return $this->deadlineAt instanceof Carbon && now()->greaterThan($this->deadlineAt);
    }

    /**
     * Whether the path is excluded from scanning.
     *
     * The `scan` list is NOT the same as `baseline`. The media disk must be in
     * the second and not in the first: excluding it from scanning means going
     * blind exactly on the upload zone.
     */
    public function isAllowlisted(string $relativePath): bool
    {
        foreach ($this->allowlist as $pattern) {
            if (PathNormalizer::matchesGlob($relativePath, $pattern)) {
                return true;
            }
        }

        return false;
    }

    public function covers(string $relativePath): bool
    {
        if ($this->restrictToPaths === []) {
            return true;
        }

        return in_array(PathNormalizer::relative($relativePath), $this->restrictToPaths, true);
    }
}
