<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

/**
 * Files that earlier scanners have already pointed at.
 *
 * Deliberately a MUTABLE object inside a readonly context: scanners run
 * sequentially (code -> uploads -> obfuscation -> hygiene), and a later one must
 * see what an earlier one found. An untracked .php from git or a file with a
 * suspicious extension in an upload zone are exactly those whose content is worth
 * reading first, even if their mtime is old.
 *
 * Candidates SUPPLEMENT the mtime gate, they do not replace it: a polyglot with
 * an innocent extension never becomes a candidate, and it is the gate that
 * catches it.
 */
final class CandidateSet
{
    /** @var array<string, string> path => the scanner that added it */
    private array $paths = [];

    public function add(string $relativePath, string $by): void
    {
        $this->paths[PathNormalizer::relative($relativePath)] = $by;
    }

    public function has(string $relativePath): bool
    {
        return isset($this->paths[PathNormalizer::relative($relativePath)]);
    }

    /**
     * @return list<string>
     */
    public function all(): array
    {
        return array_keys($this->paths);
    }

    public function count(): int
    {
        return count($this->paths);
    }
}
