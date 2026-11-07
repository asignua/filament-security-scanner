<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\Matchers\MatcherFactory;
use RuntimeException;

/**
 * Quarantine: the ONLY place in the codebase where the machine may move a file.
 *
 * Moves to storage/app/private/quarantine/{Y}/{m}/{ulid}/{basename}.quarantined.
 * A separate directory per finding means two files with the same basename never
 * collide, and the ULID leads back to the DB row without parsing the path. The
 * extension is neutralised by APPENDING, not replacing: the real name is needed
 * for forensics.
 *
 * The meta is written FIRST, the file is moved SECOND. A crash between them
 * leaves a meta without a file (recoverable), not a file without provenance
 * (not recoverable).
 *
 * The subsystem DELETES NOTHING, EVER. Even Root, who wants to remove a
 * quarantined file, does so with a separate action, and that one deletes only
 * from quarantine.
 *
 * AUTO-QUARANTINE has eight conditions in {@see mayAutoQuarantine()}, each with a
 * unit test for its false branch. Anything that fails them is manual only: EVERY
 * obfuscation finding, EVERY git finding, EVERY hygiene finding.
 *
 * MANUAL QUARANTINE is not for just any finding either: {@see move()} admits only
 * upload zones ({@see SecurityZoneKind::allowsManualQuarantine()}). A finding
 * without a zone (hygiene, git) or in `code`/`webroot`/`vendor` is left to a
 * human: moving `.env` or an application file with a panel button is not allowed,
 * it takes the site down just like auto-quarantine outside the permitted zones.
 */
final class Quarantine
{
    public const string SUFFIX = '.quarantined';

    /**
     * Whether the machine is allowed to move this finding's file by itself.
     *
     * The conditions and why they are what they are:
     *  1. both switches are on: auto is separate from enabled, because manual
     *     quarantine from the panel is needed even by a site that does not trust
     *     the automatic one;
     *  2. the rule is deterministic, i.e. it describes a FACT (extension, path),
     *     not a guess;
     *  3. matcher type is in {extension, path}: a structural guarantee that
     *     deliberately duplicates #2: the registry validator enforces it, and
     *     here it is checked once more because this is the last line before the
     *     actual move;
     *  4. the zone kind allows it: by default only upload:web. A mistake in code
     *     takes the site down, a mistake in upload:web takes away a picture that
     *     is visible and can be restored;
     *  5. the path is not in the allowlist;
     *  6. the run is not the first: the first pass on a site with a strange
     *     legacy layout must not move files before a human has looked once;
     *  7. a regular file, not a symlink, and realpath() lies INSIDE the base:
     *     the check is after realpath, not before (protection against `..`);
     *  8. size within the ceiling: moving a 2 GB video "just in case" is an
     *     incident of its own.
     */
    public static function mayAutoQuarantine(Finding $finding, Rule $rule, ScanContext $context, string $absolutePath): bool
    {
        if (!(bool) config('security-scanner.quarantine.enabled', true)
            || !(bool) config('security-scanner.quarantine.auto', false)) {
            return false;
        }

        if (!$finding->deterministic || !$rule->deterministic) {
            return false;
        }

        if (!in_array($rule->matcher::type(), MatcherFactory::deterministicTypes(), true)) {
            return false;
        }

        if (!$finding->zoneKind instanceof SecurityZoneKind || !$finding->zoneKind->allowsAutoQuarantine()) {
            return false;
        }

        // The content hash, when the finding has one, gives allowlist.hashes a
        // chance to silence THIS particular copy of the file; without it the
        // field in the rule registry exists only on paper.
        if ($context->isAllowlisted($finding->path) || $rule->isAllowlisted($finding->path, $finding->contentHash)) {
            return false;
        }

        if ($context->isFirstRun) {
            return false;
        }

        if (PathNormalizer::hasTraversal($finding->path)) {
            return false;
        }

        if (is_link($absolutePath) || !is_file($absolutePath)) {
            return false;
        }

        $real = realpath($absolutePath);
        $base = realpath($context->base);

        if ($real === false || $base === false || !str_starts_with($real, rtrim($base, '/').'/')) {
            return false;
        }

        $max = (int) config('security-scanner.quarantine.max_bytes', 67108864);

        return (int) @filesize($real) <= $max;
    }

    /**
     * Move the finding's file to quarantine. Throws on failure: a manual action
     * from the panel must show an error, not "done".
     *
     * The zone kind check goes FIRST, before any file system access, and applies
     * to BOTH paths (auto and manual): for auto it duplicates
     * {@see mayAutoQuarantine()} (the same filter is already there, here it is the
     * last line), and for manual it is the only place it exists at all; a panel
     * button could otherwise move `.env` or an `app/` file and take the site
     * down.
     */
    public static function move(SecurityFinding $finding, bool $auto, ?string $byLabel = null, ?int $byId = null): string
    {
        if (!$finding->zone_kind instanceof SecurityZoneKind || !$finding->zone_kind->allowsManualQuarantine()) {
            throw new RuntimeException((string) __('security-scanner::ui.Quarantine is available only for upload zones'));
        }

        $base = Zones::base();
        $source = rtrim($base, '/').'/'.(string) $finding->path;

        // A name that is not valid UTF-8 cannot be stored faithfully: the DB would
        // keep a U+FFFD-mangled copy and restore() would put back a DIFFERENT file
        // name. The row keeps an escaped path (`\xFF`) that no longer opens the
        // file, so such a name is refused up front and the finding stays open.
        if (!mb_check_encoding((string) $finding->path, 'UTF-8')
            || (!is_file($source) && PathNormalizer::wasAltered((string) $finding->path))) {
            throw new RuntimeException(self::nonUtf8Message());
        }

        $zoneReal = self::zoneRoot($finding);

        if (is_link($source) || !is_file($source)) {
            throw new RuntimeException(sprintf('The file does not exist or is a symlink: %s', (string) $finding->path));
        }

        $real = realpath($source);
        $realBase = realpath($base);

        if ($real === false || $realBase === false || !str_starts_with($real, rtrim($realBase, '/').'/')) {
            throw new RuntimeException('The path escapes the project');
        }

        self::assertSourceInZone($source, $real, $zoneReal);

        if (!mb_check_encoding($real, 'UTF-8')) {
            throw new RuntimeException(self::nonUtf8Message());
        }

        $dir = self::root().'/'.now()->format('Y/m').'/'.$finding->ulid;

        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            throw new RuntimeException('Failed to create the quarantine directory');
        }

        self::ensureGuard();

        $target = $dir.'/'.basename($real).self::SUFFIX;

        // The same finding (ulid, hence the same directory) is quarantined again:
        // the file was restored and is suspicious once more. `rename()` would
        // silently overwrite the previous forensic copy, so a taken basename gets
        // a number instead of being overwritten.
        if (file_exists($target)) {
            $copy = 2;

            do {
                $target = $dir.'/'.basename($real).'.'.$copy.self::SUFFIX;
                $copy++;
            } while (file_exists($target));
        }

        $metaPath = $dir.'/'.self::metaFilenameFor(basename($target));

        $meta = [
            'finding' => $finding->ulid,
            'original_path' => (string) $finding->path,
            'absolute_path' => $real,
            'sha256' => @hash_file('sha256', $real) ?: null,
            'size' => @filesize($real) ?: 0,
            'mtime' => @filemtime($real) ?: 0,
            'mode' => sprintf('%04o', (@fileperms($real) ?: 0) & 0777),
            'rule' => $finding->rule_id,
            'scan' => $finding->last_scan_id,
            'auto' => $auto,
            'by' => $byLabel,
            'at' => now()->toIso8601String(),
        ];

        // Meta FIRST. A crash on rename leaves a meta without a file, which is
        // recoverable; a file without meta is not.
        if (@file_put_contents($metaPath, json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)) === false) {
            throw new RuntimeException('Failed to write the quarantine meta');
        }

        // Re-checked IMMEDIATELY before the move: a directory swapped for a symlink
        // since the first check must not redirect the rename.
        self::assertSourceInZone($source, $real, $zoneReal);

        if (!@rename($real, $target)) {
            throw new RuntimeException(sprintf('Failed to move %s', (string) $finding->path));
        }

        @chmod($target, 0600);

        $finding->status = SecurityFindingStatus::Quarantined;
        $finding->status_changed_at = now();
        $finding->status_by_id = $byId;
        $finding->status_by_label = $byLabel ?? ($auto ? 'auto' : null);
        $finding->quarantine_path = PathNormalizer::relative($target, $base);
        $finding->quarantined_at = now();
        $finding->quarantine_auto = $auto;
        $finding->save();

        return $target;
    }

    /**
     * Put the file back. ONLY if the original path is still free: an occupied
     * path means a loud refusal, never an overwrite.
     */
    public static function restore(SecurityFinding $finding, ?string $byLabel = null, ?int $byId = null): void
    {
        $base = Zones::base();
        $quarantined = $finding->quarantine_path;

        if (!is_string($quarantined) || $quarantined === '') {
            throw new RuntimeException('The finding is not in quarantine');
        }

        $source = rtrim($base, '/').'/'.$quarantined;
        $target = rtrim($base, '/').'/'.(string) $finding->path;

        if (!is_file($source)) {
            throw new RuntimeException('The quarantined file is not on disk');
        }

        // The source is controlled too: `quarantine_path` is a DB field, not
        // trusted input, and must lead exactly into the quarantine directory, not
        // anywhere in the project.
        $sourceReal = realpath($source);
        $rootReal = realpath(self::root());

        if ($sourceReal === false || $rootReal === false || !str_starts_with($sourceReal, rtrim($rootReal, '/').'/')) {
            throw new RuntimeException('The path escapes the project');
        }

        $zoneReal = self::zoneRoot($finding);

        if (file_exists($target)) {
            throw new RuntimeException(sprintf('The original path is already taken: %s', (string) $finding->path));
        }

        // Mirror of the source check in move(): if an intermediate directory of
        // the original path has been replaced with a symlink pointing outside the
        // project, is_dir() in the branch below would follow it, and a legitimate
        // Root action ("Restore from quarantine") would write the file outside
        // the tree.
        self::assertDestinationContained($base, dirname((string) $finding->path));

        $targetDir = dirname($target);

        if (!is_dir($targetDir) && !@mkdir($targetDir, 0755, true)) {
            throw new RuntimeException('Failed to create the destination directory');
        }

        // Right before the move: the destination directory (now created, if it
        // was missing) must resolve INSIDE the zone, not merely inside the project.
        $targetDirReal = realpath($targetDir);

        if ($targetDirReal === false || !self::isWithin($targetDirReal, $zoneReal)) {
            throw new RuntimeException('The destination path escapes the zone');
        }

        if (is_link($target) || !@rename($source, $target)) {
            throw new RuntimeException('Failed to restore the file');
        }

        $metaPath = dirname($source).'/'.self::metaFilenameFor(basename($source));
        $meta = @json_decode((string) @file_get_contents($metaPath), true);

        if (is_array($meta) && is_string($meta['mode'] ?? null)) {
            @chmod($target, (int) octdec($meta['mode']));
        }

        // The restored file is a LIVE file again, possibly a live web shell: the
        // finding is reopened as NEW with its notification stamps cleared, so every
        // channel alerts once more. `Acknowledged` here used to keep the next scan
        // silent. An admin who restored a false positive closes it with `Ignore`.
        // `quarantined_at` goes too: nothing is in quarantine any more.
        $finding->status = SecurityFindingStatus::New;
        $finding->status_changed_at = now();
        $finding->status_by_id = $byId;
        $finding->status_by_label = $byLabel;
        $finding->status_note = (string) __('security-scanner::ui.Restored from quarantine');
        $finding->quarantine_path = null;
        $finding->quarantined_at = null;
        $finding->quarantine_auto = false;
        $finding->notified_channels = null;
        $finding->notified_at = null;
        $finding->save();
    }

    /**
     * Real path of the zone root the finding's file must stay in. A path with a
     * `..` segment, or one that lies in no zone, is refused: the stored path is a
     * DB value, not trusted input.
     */
    private static function zoneRoot(SecurityFinding $finding): string
    {
        $path = (string) $finding->path;

        if (PathNormalizer::hasTraversal($path) || PathNormalizer::hasTraversal((string) $finding->quarantine_path)) {
            throw new RuntimeException('The path escapes the zone');
        }

        $zone = Zones::forPath($path, $finding->zone);
        $real = $zone instanceof Zone ? realpath($zone->absolutePath) : false;

        if ($real === false) {
            throw new RuntimeException('The path is not inside a scanned zone');
        }

        return rtrim($real, '/');
    }

    /**
     * The file AND its parent directory must resolve inside the zone root.
     */
    private static function assertSourceInZone(string $source, string $real, string $zoneReal): void
    {
        $parent = realpath(dirname($source));

        if (!self::isWithin($real, $zoneReal) || $parent === false || !self::isWithin($parent, $zoneReal)) {
            throw new RuntimeException('The path escapes the zone');
        }

        if (realpath($source) !== $real) {
            throw new RuntimeException('The path changed while being checked');
        }
    }

    private static function isWithin(string $path, string $root): bool
    {
        $path = rtrim($path, '/');

        return $path === $root || str_starts_with($path, $root.'/');
    }

    private static function nonUtf8Message(): string
    {
        return (string) __('security-scanner::ui.Quarantine refused: the file name is not valid UTF-8. The finding stays open; handle the file by hand.');
    }

    public static function root(): string
    {
        return rtrim(Zones::base(), '/').'/storage/app/private/quarantine';
    }

    /**
     * A .gitignore with `*` at the quarantine root: even if someone one day
     * removes storage/app from ignoring, the shells will not end up in the
     * repository.
     */
    private static function ensureGuard(): void
    {
        $guard = self::root().'/.gitignore';

        if (!is_file($guard)) {
            @file_put_contents($guard, "*\n!.gitignore\n");
        }
    }

    /**
     * Destination containment for `restore()`. `realpath()` is not suitable
     * directly here: the destination directory (or part of it) may not exist
     * yet, which is why the check goes component by component FROM `$base`
     * DOWNWARDS, not the other way round: a symlink that replaced an
     * intermediate directory is caught before `is_dir()` in the `mkdir` branch
     * can follow it.
     */
    private static function assertDestinationContained(string $base, string $relativeDir): void
    {
        $baseReal = realpath($base);

        if ($baseReal === false) {
            throw new RuntimeException('The destination path escapes the project');
        }

        $baseReal = rtrim($baseReal, '/');
        $deepestExistingPath = $baseReal;

        foreach (explode('/', $relativeDir) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            $candidate = $deepestExistingPath.'/'.$segment;

            if (!file_exists($candidate)) {
                // The remaining components do not exist yet: mkdir() will create
                // them empty, so there is nothing there to replace with a symlink.
                break;
            }

            if (is_link($candidate)) {
                throw new RuntimeException('The destination path escapes the project');
            }

            $deepestExistingPath = $candidate;
        }

        $deepestExistingReal = realpath($deepestExistingPath);

        if ($deepestExistingReal === false || !str_starts_with($deepestExistingReal.'/', $baseReal.'/')) {
            throw new RuntimeException('The destination path escapes the project');
        }
    }

    /**
     * Meta file name of a copy: the first stays `meta.json` (as always), each
     * following one is `meta-<n>.json` with the same number as in
     * `<basename>.<n>.quarantined`, so that `restore()` reads the meta of the
     * very copy it restores, not always the first one.
     */
    private static function metaFilenameFor(string $targetBasename): string
    {
        if (preg_match('/\.(\d+)'.preg_quote(self::SUFFIX, '/').'$/', $targetBasename, $m) === 1) {
            return 'meta-'.$m[1].'.json';
        }

        return 'meta.json';
    }
}
