<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

/**
 * Brings paths to a single form for fingerprints, allowlists and globs.
 *
 * Why a separate class: a finding's fingerprint is built from the path, so any
 * spelling discrepancy ("./a/b", "a//b", "a/b/") would give a DIFFERENT fingerprint and a new
 * finding every night on the same file. Normalization must be single for the whole
 * subsystem and pure, hence no FS access: we do not call `realpath()` here,
 * because it resolves symlinks (and a symlink in an upload zone is a finding in itself,
 * so it must not be replaced by its target) and returns false for a just-deleted file.
 */
final class PathNormalizer
{
    /** Length of the `path`/`quarantine_path` columns in `security_findings`. */
    public const int MAX_STORED_LENGTH = 400;

    /**
     * A valid UTF-8 character without control ones: printable ASCII or a correct
     * multibyte sequence (no overlong forms or surrogates).
     */
    private const string VALID_CHAR = '~\G(?:[\x20-\x7E]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]'
        .'|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}'
        .'|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2})~';

    /**
     * A path in a form guaranteed to fit into the DB column.
     *
     * A file name on Linux is arbitrary bytes, and the path length is not
     * limited by the column. A raw path in a `string(400)` utf8mb4 on strict MySQL throws
     * ("Incorrect string value" / "Data too long"), and this used to end the
     * WHOLE scanner: it was enough for an attacker to name a shell `x\xff.php` to hide both
     * it and everything the walk was supposed to see after it.
     *
     * Invalid and control bytes become `\xNN` (the same as evidence excerpts), an overlong
     * path becomes the beginning + `…#` + 16 chars of sha256 of the FULL raw path: two different
     * deep paths with a common beginning do not collapse. The finding's fingerprint
     * is computed from the raw path, so dedup does not depend on this.
     *
     * THIS IS A VIEW FOR HUMANS, NOT FOR THE FS: such a string no longer opens the file;
     * {@see wasAltered()} says when it cannot be relied upon.
     */
    public static function storable(string $path, int $max = self::MAX_STORED_LENGTH): string
    {
        $out = self::escapeBytes($path);

        if (mb_strlen($out) <= $max) {
            return $out;
        }

        return mb_substr($out, 0, $max - 18).'…#'.substr(hash('sha256', $path), 0, 16);
    }

    /**
     * Whether the stored path is no longer the real path on disk (escaped bytes or
     * a truncated tail). A false match on a file that literally contains `\x41` in its
     * name is harmless: it only disables auto-actions over the row, not the finding.
     */
    public static function wasAltered(string $stored): bool
    {
        return preg_match('~\\\\x[0-9A-F]{2}|…#[0-9a-f]{16}\z~u', $stored) === 1;
    }

    /**
     * Valid UTF-8 characters stay as they are, the remaining bytes (broken UTF-8, control,
     * DEL) become `\xNN`. The result is always valid UTF-8 and safe for JSON with
     * JSON_THROW_ON_ERROR.
     */
    public static function escapeBytes(string $value): string
    {
        if (mb_check_encoding($value, 'UTF-8') && preg_match('~[\x00-\x1F\x7F]~', $value) !== 1) {
            return $value;
        }

        $out = '';
        $offset = 0;
        $length = strlen($value);

        while ($offset < $length) {
            if (preg_match(self::VALID_CHAR, $value, $m, 0, $offset) === 1) {
                $out .= $m[0];
                $offset += strlen($m[0]);

                continue;
            }

            $out .= sprintf('\x%02X', ord($value[$offset]));
            $offset++;
        }

        return $out;
    }

    /**
     * A relative POSIX path without "./", double slashes and a trailing slash.
     * An absolute path lying under $base becomes relative to it.
     */
    public static function relative(string $path, ?string $base = null): string
    {
        // A backslash is a separator only where the OS says so. On POSIX it is an
        // ordinary file name character: turning `..\..\public\index.php` (ONE file
        // name) into `../../public/index.php` made a planted file name a traversal.
        $path = self::toSlashes($path);

        if ($base !== null) {
            $base = rtrim(self::toSlashes($base), '/');

            if ($base !== '' && str_starts_with($path, $base.'/')) {
                $path = substr($path, strlen($base) + 1);
            }
        }

        $path = (string) preg_replace('~/+~', '/', $path);
        $path = (string) preg_replace('~(^|/)\./~', '$1', $path);
        $path = ltrim($path, '/');

        return rtrim($path, '/');
    }

    private static function toSlashes(string $path): string
    {
        return DIRECTORY_SEPARATOR === '\\' ? str_replace('\\', '/', $path) : $path;
    }

    /**
     * Whether a stored relative path has a `.`/`..` or empty-after-trim segment that
     * could leave the directory it is joined to. Segments are split on `/` only.
     */
    public static function hasTraversal(string $path): bool
    {
        foreach (explode('/', $path) as $segment) {
            if ($segment === '..') {
                return true;
            }
        }

        return str_contains($path, "\0");
    }

    /**
     * The extension chain in LOWER case, from last to first:
     * "archive.tar.gz" → ['gz', 'tar'], "baal.php.jpg" → ['jpg', 'php'].
     *
     * The case is lowered necessarily: the media disk already holds a file with the
     * extension "PNG", and `shell.PHP` is executed by the same php-fpm as
     * `shell.php`. A case-sensitive extension matcher is a hole by construction.
     *
     * A leading dot in the name is NOT considered an extension: ".htaccess" has an
     * empty chain, and it is caught by a rule on the NAME, not on the extension.
     *
     * @return list<string>
     */
    public static function extensionChain(string $path): array
    {
        $name = basename(self::relative($path));
        $name = ltrim($name, '.');

        if ($name === '' || !str_contains($name, '.')) {
            return [];
        }

        $parts = explode('.', $name);
        array_shift($parts);                       // the file name itself, not an extension

        $parts = array_map(
            static fn (string $p): string => strtolower(trim($p)),
            $parts,
        );

        return array_values(array_reverse(array_filter(
            $parts,
            static fn (string $p): bool => $p !== '',
        )));
    }

    /**
     * Whether the path falls under an allowlist glob pattern. `**` covers any
     * number of segments, `*` only one segment (it does not cross "/").
     *
     * A custom implementation rather than `fnmatch()`: it is platform-dependent (on some
     * Windows builds it simply does not exist) and does not distinguish `*` from `**`, so an
     * entry like `storage/*` would silently cover the entire subtree content together with the zone
     * that is exactly what needs to be scanned.
     */
    public static function matchesGlob(string $path, string $pattern, bool $ignoreCase = false): bool
    {
        $path = self::relative($path);
        $pattern = self::relative($pattern);

        $regex = '';
        $length = strlen($pattern);

        for ($i = 0; $i < $length; $i++) {
            $char = $pattern[$i];

            if ($char === '*') {
                if (($pattern[$i + 1] ?? '') === '*') {
                    $i++;

                    // "**/" must also cover zero segments: pattern "a/**/b" is equivalent to "a/b".
                    if (($pattern[$i + 1] ?? '') === '/') {
                        $i++;
                        $regex .= '(?:.*/)?';
                    } else {
                        $regex .= '.*';
                    }
                } else {
                    $regex .= '[^/]*';
                }

                continue;
            }

            if ($char === '?') {
                $regex .= '[^/]';

                continue;
            }

            $regex .= preg_quote($char, '~');
        }

        return (bool) preg_match('~^'.$regex.'$~'.($ignoreCase ? 'i' : ''), $path);
    }

    /**
     * Whether the path lies inside the root. The comparison is STRING-based, on already normalized
     * paths; the check "did we leave the zone boundary" after resolve is done
     * separately in {@see Quarantine}, where the FS is available.
     */
    public static function isInside(string $path, string $root): bool
    {
        $path = self::relative($path);
        $root = self::relative($root);

        return $root === '' || $path === $root || str_starts_with($path, $root.'/');
    }
}
