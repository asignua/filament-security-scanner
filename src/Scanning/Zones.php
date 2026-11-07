<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Illuminate\Support\Facades\Storage;
use Throwable;

/**
 * Resolves `security-scanner.zones` into concrete directories.
 *
 * A zone that could not be resolved (no disk, no directory) does NOT vanish
 * silently: it is returned in a separate list of issues. Silently skipping a zone
 * is the same class of failure as a dead scanner: the report looks clean
 * precisely because nobody looked anywhere.
 */
final class Zones
{
    /**
     * @return array{0: list<Zone>, 1: list<string>}
     */
    public static function resolve(?string $base = null): array
    {
        $base = $base ?? self::base();
        $zones = [];
        $issues = [];

        /** @var array<string, mixed> $configured */
        $configured = (array) config('security-scanner.zones', []);

        foreach ($configured as $name => $definition) {
            $name = (string) $name;

            if (!is_array($definition)) {
                $issues[] = sprintf('zone "%s": the definition must be an array', $name);

                continue;
            }

            $kind = is_string($definition['kind'] ?? null)
                ? SecurityZoneKind::tryFrom($definition['kind'])
                : null;

            if ($kind === null) {
                $issues[] = sprintf('zone "%s": unknown kind', $name);

                continue;
            }

            $path = null;
            $disk = null;

            if (is_string($definition['root'] ?? null) && $definition['root'] !== '') {
                $path = rtrim($base, '/').'/'.ltrim($definition['root'], '/');
            } elseif (is_string($definition['disk'] ?? null) && $definition['disk'] !== '') {
                $disk = $definition['disk'];

                try {
                    $path = Storage::disk($disk)->path('');
                } catch (Throwable $e) {
                    $issues[] = sprintf('zone "%s": disk "%s" is unavailable: %s', $name, $disk, $e->getMessage());

                    continue;
                }
            }

            if ($path === null) {
                $issues[] = sprintf('zone "%s": exactly one of root or disk is required', $name);

                continue;
            }

            $zone = new Zone($name, $kind, rtrim($path, '/'), $disk);

            if (!$zone->exists()) {
                // Not a config error but a fact: the directory may be absent on this
                // site (no videos, no storage/videos). But it must still be reported.
                $issues[] = sprintf('zone "%s": directory does not exist (%s)', $name, $zone->absolutePath);

                continue;
            }

            $zones[] = $zone;
        }

        [$zones, $nestingIssues] = self::resolveNesting($zones);

        return [$zones, array_merge($issues, $nestingIssues)];
    }

    /**
     * Gives each zone the directories of the more specific zones nested in it.
     *
     * Zones do NOT exclude one another in the config and need not: `storage_app`
     * describes the whole application uploads directory, while `storage_public`
     * and the media disk sit inside it because they have a different KIND
     * (auto-quarantine is allowed only in a zone reachable from the web). Who
     * covers whom is a question of a particular site's layout, so the answer is
     * taken from the file system, not from the config.
     *
     * Nesting is computed via `realpath()` (a symlink in a path segment would
     * otherwise make two identical directories different strings), while the
     * exclusions are COMPOSED back onto the parent's raw `absolutePath`: the walk
     * generates paths from exactly that, and prefix comparison must happen in the
     * same coordinate system.
     *
     * @param list<Zone> $zones
     *
     * @return array{0: list<Zone>, 1: list<string>}
     */
    private static function resolveNesting(array $zones): array
    {
        $issues = [];
        $real = array_map(
            static fn (Zone $z): string => rtrim((string) (realpath($z->absolutePath) ?: $z->absolutePath), '/'),
            $zones,
        );

        foreach ($zones as $i => $zone) {
            $excluded = [];

            foreach ($zones as $j => $other) {
                if ($i === $j) {
                    continue;
                }

                if ($real[$i] === $real[$j]) {
                    // Not nesting but a duplicate: both zones would walk the same
                    // directory, and the finding's kind would be decided by the key
                    // order in the config. We drop neither: a zone silently
                    // disappearing is the same class of failure this issue list
                    // exists for.
                    if ($i < $j) {
                        $issues[] = sprintf('zones "%s" and "%s" point to the same directory (%s)', $zone->name, $other->name, $real[$i]);
                    }

                    continue;
                }

                if (!str_starts_with($real[$j], $real[$i].'/')) {
                    continue;
                }

                $excluded[] = rtrim($zone->absolutePath, '/').substr($real[$j], strlen($real[$i]));
            }

            if ($excluded !== []) {
                $zones[$i] = $zone->withExcludedRoots($excluded);
            }
        }

        return [$zones, $issues];
    }

    public static function base(): string
    {
        return rtrim(function_exists('base_path') ? base_path() : (string) getcwd(), '/');
    }
}
