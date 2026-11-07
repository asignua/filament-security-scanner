<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;

/**
 * What the matcher sees: one file, already read exactly as far as the scanner
 * allowed.
 *
 * Matchers do NOT go to the filesystem themselves; they are handed a ready snapshot. This is not
 * style but necessity: the zone walk has its own budget (69k files on a
 * media disk), so the decision "read content or not" is made by the scanner once, not by
 * each rule separately. A side effect is that the whole matcher layer is tested without the
 * FS at all.
 *
 * `$bytes === null` means "content was NOT read", not "the file is empty". Content
 * matchers on such a subject must return empty rather than assume it is clean.
 */
final readonly class MatchSubject
{
    /**
     * @param list<string> $extensionChain extensions from last to first, lowercase
     */
    public function __construct(
        public string $path,
        public string $basename,
        public array $extensionChain,
        public SecurityZoneKind $zoneKind,
        public int $size = 0,
        public ?string $bytes = null,
        public bool $isSymlink = false,
    ) {}

    /**
     * Build a subject from a path and (optionally) content. The path is normalized
     * here, not at each call site; otherwise a finding's fingerprint would depend on
     * who wrote the path and how.
     */
    public static function make(
        string $path,
        SecurityZoneKind $zoneKind,
        ?string $base = null,
        int $size = 0,
        ?string $bytes = null,
        bool $isSymlink = false,
    ): self {
        $relative = PathNormalizer::relative($path, $base);

        return new self(
            path: $relative,
            basename: basename($relative),
            extensionChain: PathNormalizer::extensionChain($relative),
            zoneKind: $zoneKind,
            size: $size,
            bytes: $bytes,
            isSymlink: $isSymlink,
        );
    }

    public function hasContent(): bool
    {
        return $this->bytes !== null;
    }

    /**
     * The last extension or null for files without an extension (`.htaccess`).
     */
    public function extension(): ?string
    {
        return $this->extensionChain[0] ?? null;
    }
}
