<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use FilesystemIterator;
use Generator;
use RecursiveCallbackFilterIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * A resolved zone: config name + kind + absolute root on disk.
 *
 * The config describes a zone with either `root` (a path from the project root)
 * or `disk` (a Laravel filesystem disk name), exactly one of the two. The disk
 * matters for more than looks: a site's media disk can live anywhere, and a
 * hard-coded path in the package config would diverge from reality on the very
 * first site with a different layout.
 *
 * **Limitation (known issue):** the zone root MUST lie under `base_path()`.
 * Reason: `PathNormalizer::relative()` strips the base path only when the path is
 * under it; a zone outside it (e.g. a media disk in `/data/media`) yields a
 * pseudo-relative path (`data/media/x`) that every consumer again resolves as
 * `base_path().'/'.path`: quarantine will say "file not found",
 * `reverifyUnseen()` closes and reopens the finding every night, and fingerprints
 * may collide with a real `data/...` path. Deliberately not solved: no site on
 * the package is configured that way.
 *
 * **Nested zones.** Zones may lie inside one another: `storage_app` covers the
 * whole application uploads directory, while `storage_public` and the site's
 * media disk sit inside it and are described separately because they have a
 * different KIND. The directory of the more specific zone is cut out of the walk
 * of the more general one ({@see Zones::resolve()} fills `$excludedRoots`);
 * otherwise a production media disk (71,786 files) would be walked twice, and a
 * finding's zone kind would be decided by the order of keys in the config: a file
 * from `storage/app/public` could arrive as `upload:private` and silently fall
 * out of auto-quarantine.
 */
final readonly class Zone
{
    /**
     * @param list<string> $excludedRoots absolute roots of nested zones: directories
     *                                    that belong to a more specific zone
     */
    public function __construct(
        public string $name,
        public SecurityZoneKind $kind,
        public string $absolutePath,
        public ?string $disk = null,
        public array $excludedRoots = [],
    ) {}

    /**
     * @param list<string> $roots
     */
    public function withExcludedRoots(array $roots): self
    {
        return new self($this->name, $this->kind, $this->absolutePath, $this->disk, $roots);
    }

    /**
     * The file path relative to the PROJECT root, not to the zone.
     */
    public function relative(string $absolute, string $base): string
    {
        return PathNormalizer::relative($absolute, $base);
    }

    public function exists(): bool
    {
        return is_dir($this->absolutePath);
    }

    /**
     * Whether a relative path (from the project root) lies INSIDE this zone.
     */
    public function contains(string $relativePath, string $base): bool
    {
        return PathNormalizer::isInside($relativePath, $this->relative($this->absolutePath, $base));
    }

    /**
     * Whether the path belongs to THIS zone, not to a more specific one nested in it.
     *
     * `contains()` remains geometry (the path is under the root), and it is what
     * is needed when the question is "is this my branch of the tree at all".
     * Ownership is a different question, and its answer must be single across the
     * whole zone set: a file given to two zones gets the kind of the one that came
     * first in the config.
     */
    public function owns(string $relativePath, string $base): bool
    {
        return $this->contains($relativePath, $base)
            && !$this->excludes(rtrim($base, '/').'/'.ltrim(PathNormalizer::relative($relativePath), '/'));
    }

    /**
     * Whether the absolute path lies in the directory of a nested (more specific) zone.
     */
    public function excludes(string $absolutePath): bool
    {
        $path = rtrim($absolutePath, '/');

        foreach ($this->excludedRoots as $root) {
            if ($path === $root || str_starts_with($path, $root.'/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursive zone walk: ONE for all three places that walk trees
     * (structural scanner, hash snapshot/obfuscation, hygiene). It is shared for
     * more than looks: cutting out nested zones in only one of them would give
     * scanners with different ideas of what belongs to a zone.
     *
     * Directories of nested zones are cut off by a FILTER, not by a check on
     * output: a `RecursiveCallbackFilterIterator` that returned `false` on a
     * directory does not descend into it at all; otherwise the cost would stay
     * full (71,786 media disk files would be enumerated just to be discarded one
     * by one).
     *
     * FOLLOW_SYMLINKS is never enabled: leaving the zone is something to be
     * flagged, not something to follow.
     *
     * A directory that cannot be opened is skipped (CATCH_GET_CHILD) but RECORDED
     * in `$unreadable`: a skipped directory is "not looked at", never "clean".
     *
     * @param RecursiveIteratorIterator::CHILD_FIRST|RecursiveIteratorIterator::LEAVES_ONLY|RecursiveIteratorIterator::SELF_FIRST $mode
     *
     * @return RecursiveIteratorIterator<RecursiveCallbackFilterIterator<mixed, mixed, ZoneDirectoryIterator>|ZoneDirectoryIterator>
     */
    public function iterator(int $mode = RecursiveIteratorIterator::LEAVES_ONLY, ?UnreadableDirectories $unreadable = null): RecursiveIteratorIterator
    {
        $directory = new ZoneDirectoryIterator(
            $this->absolutePath,
            FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO,
        );
        $directory->unreadable = $unreadable;

        $inner = $this->excludedRoots === []
            ? $directory
            : new RecursiveCallbackFilterIterator(
                $directory,
                fn (SplFileInfo $file): bool => !$this->excludes($file->getPathname()),
            );

        return new RecursiveIteratorIterator($inner, $mode, RecursiveIteratorIterator::CATCH_GET_CHILD);
    }

    /**
     * Zone candidates narrowed to specific paths; this is how the reaction to
     * uploads (A10) works. Instead of walking the whole zone (69,565 files on a
     * production media disk) we do one `file_exists()` per EACH given path: the
     * cost of a targeted run becomes O(number of paths), not O(zone size).
     *
     * `file_exists()` ALONE is not enough: it follows the link and silently
     * returns `false` for a DANGLING symlink, so such a path would drop out of
     * the generator entirely and no downstream code would ever see it. `walk()`
     * always catches this target (`isLink()` BEFORE `isDir()`), so a narrowed pass
     * has no right to see less; hence the additional `is_link()`: a symlink,
     * live or with a broken target, is yielded in any case, and dealing with it
     * (isLink()/isDir()) is up to the scanners' downstream code, as for a regular
     * file.
     *
     * @param list<string> $relativePaths
     *
     * @return Generator<SplFileInfo>
     */
    public function restrictedCandidates(array $relativePaths, string $base): Generator
    {
        foreach ($relativePaths as $relativePath) {
            if (!$this->owns($relativePath, $base)) {
                continue;
            }

            $absolute = rtrim($base, '/').'/'.$relativePath;

            if (!file_exists($absolute) && !is_link($absolute)) {
                continue;
            }

            yield new SplFileInfo($absolute);
        }
    }
}
