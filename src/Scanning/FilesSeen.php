<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

/**
 * How many DISTINCT files the run actually inspected.
 *
 * Mutable, like {@see CandidateSet} and {@see ScanIssues}, and for the same
 * reason: scanners write here one by one, and ScanRunner reads the total at the
 * end of the run. Deliberately SEPARATE from CandidateSet: that one is
 * responsible for "read the content even on an old mtime", and if every visited
 * file were counted into it, the mtime gate would be switched off forever
 * (candidates->has() forces reading of any file that appears there).
 *
 * Its direct purpose is to prove action A10: a narrowed pass (reaction to an
 * upload) must see exactly as many files as the paths it was given, not the
 * whole zone.
 */
final class FilesSeen
{
    /** @var array<string, true> */
    private array $paths = [];

    public function add(string $relativePath): void
    {
        $this->paths[PathNormalizer::relative($relativePath)] = true;
    }

    public function count(): int
    {
        return count($this->paths);
    }
}
