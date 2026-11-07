<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

/**
 * Directories a zone walk could not open.
 *
 * A directory the web user cannot list (`chmod 0311`) can still EXECUTE a file
 * inside it by name. Skipping it silently made the walk look complete, so findings
 * under it were closed as "gone". The walk records such directories here instead,
 * and the scanner turns them into an issue and an incomplete pass.
 */
final class UnreadableDirectories
{
    /** @var list<string> */
    private array $paths = [];

    public function add(string $absolutePath): void
    {
        $this->paths[] = $absolutePath;
    }

    /**
     * @return list<string>
     */
    public function all(): array
    {
        return $this->paths;
    }

    public function isEmpty(): bool
    {
        return $this->paths === [];
    }
}
