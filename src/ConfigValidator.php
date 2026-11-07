<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;

/**
 * Scanner config validation. Empty zones and mixed-up exclusion lists give the
 * SAME symptom: the scanner runs, reports "clean" and looks
 * nowhere — the worst failure mode of a detection subsystem; it is caught only here.
 * A missing section is not an error (a config cached before the package appeared).
 */
final class ConfigValidator
{
    /**
     * @return list<string>
     */
    public static function check(): array
    {
        $config = config('security-scanner');

        if (!is_array($config)) {
            return [];
        }

        $issues = [];
        $checks = [
            'zones' => self::zones(...),
            'allowlist' => self::allowlist(...),
            'notify.min_severity' => self::minSeverity(...),
            'quarantine.auto_zones' => self::autoZones(...),
            'telegram.chat_id' => self::telegramPair(...),
            'retention_days' => self::nonNegativeInt(...),
            'max_file_size' => self::nonNegativeInt(...),
            'notify.throttle_minutes' => self::nonNegativeInt(...),
            'upload.sync_budget_ms' => self::nonNegativeInt(...),
        ];

        foreach ($checks as $key => $check) {
            $error = $check(data_get($config, $key), $config);

            if ($error !== null) {
                $issues[] = sprintf('config security-scanner.%s: %s', $key, $error);
            }
        }

        return $issues;
    }

    /**
     * Scanner zones. An empty set does not mean "check nothing" but silent blindness:
     * the scanner runs, reports "clean" and looks nowhere. Hence it is an error.
     *
     * @param array<string, mixed> $config
     */
    private static function zones(mixed $value, array $config): ?string
    {
        // The key may be missing from the RESOLVED config if a deploy cached it
        // before the feature appeared. Then we stay silent: otherwise the host's environment-check command
        // in post-update-cmd would fail on exactly the deploy that brings this feature.
        if ($value === null) {
            return null;
        }

        // But an explicitly empty set is an error, and not a cosmetic one: the scanner runs,
        // reports "clean" and looks nowhere. Silent blindness is worse than a failure.
        if (!is_array($value) || $value === []) {
            return 'no zones configured — the scanner will not look anywhere';
        }

        $kinds = array_map(static fn (SecurityZoneKind $k): string => $k->value, SecurityZoneKind::cases());

        foreach ($value as $name => $zone) {
            if (!is_array($zone)) {
                return sprintf('zone "%s" must be an array', (string) $name);
            }

            $kind = $zone['kind'] ?? null;

            if (!is_string($kind) || !in_array($kind, $kinds, true)) {
                return sprintf('zone "%s": kind must be one of %s', (string) $name, implode(', ', $kinds));
            }

            $hasRoot = isset($zone['root']) && is_string($zone['root']) && $zone['root'] !== '';
            $hasDisk = isset($zone['disk']) && is_string($zone['disk']) && $zone['disk'] !== '';

            if ($hasRoot === $hasDisk) {
                return sprintf('zone "%s": exactly one of `root` or `disk` is required', (string) $name);
            }
        }

        return null;
    }

    /**
     * Two exclusion lists. The costliest mistake here is putting the media disk into `scan`
     * instead of `baseline`: the media disk must be in `baseline` (do not hash
     * the mutable uploads disk), and not in `scan` — otherwise the scanner quietly stops
     * looking at exactly the zone it was introduced for.
     *
     * @param array<string, mixed> $config
     */
    private static function allowlist(mixed $value, array $config): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_array($value)) {
            return 'allowlist must be an array';
        }

        foreach (['scan', 'baseline'] as $key) {
            $list = $value[$key] ?? null;

            if (!is_array($list)) {
                return sprintf('allowlist.%s must be a list of glob patterns', $key);
            }

            foreach ($list as $pattern) {
                if (!is_string($pattern) || $pattern === '') {
                    return sprintf('allowlist.%s contains an empty or non-string pattern', $key);
                }
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function minSeverity(mixed $value, array $config): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_array($value)) {
            return 'min_severity must be a channel => level map';
        }

        foreach ($value as $channel => $level) {
            if (!is_string($level) || SecuritySeverity::tryFromName($level) === null) {
                return sprintf('channel "%s": unknown level "%s"', (string) $channel, is_scalar($level) ? (string) $level : gettype($level));
            }
        }

        return null;
    }

    /**
     * Token and chat_id are a pair. A token without chat_id is a channel that looks
     * configured and sends nothing; such failures stay unnoticed
     * the longest.
     *
     * @param array<string, mixed> $config
     */
    private static function telegramPair(mixed $value, array $config): ?string
    {
        $chatId = is_string($value) ? trim($value) : '';
        $token = is_string($config['telegram']['token'] ?? null) ? trim($config['telegram']['token']) : '';

        if ($token !== '' && $chatId === '') {
            return 'SECURITY_SCANNER_TELEGRAM_BOT_TOKEN is set but SECURITY_SCANNER_TELEGRAM_CHAT_ID is not — the channel will be silent';
        }

        if ($chatId !== '' && $token === '') {
            return 'SECURITY_SCANNER_TELEGRAM_CHAT_ID is set but SECURITY_SCANNER_TELEGRAM_BOT_TOKEN is not';
        }

        return null;
    }

    /**
     * Auto-quarantine in code zones is a way to take a site down with one false
     * positive. Hence only upload zones are allowed.
     *
     * @param array<string, mixed> $config
     */
    private static function autoZones(mixed $value, array $config): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_array($value)) {
            return 'auto_zones must be a list';
        }

        foreach ($value as $kind) {
            $resolved = is_string($kind) ? SecurityZoneKind::tryFrom($kind) : null;

            if ($resolved === null || !$resolved->isUploadZone()) {
                return sprintf('auto_zones: "%s" — only upload:web and upload:private are allowed', is_scalar($kind) ? (string) $kind : gettype($kind));
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function nonNegativeInt(mixed $value, array $config): ?string
    {
        if ($value === null) {
            return null;
        }

        return is_int($value) && $value >= 0 ? null : 'an integer >= 0 is expected';
    }
}
