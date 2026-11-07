<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Scanning\Exceptions\InvalidSecurityRuleException;
use Throwable;

/**
 * Loads and merges the heuristics registry from two files.
 *
 * Priority (the last one wins PER id): `package` -> `host`.
 *
 * The merge is mechanical because the host never edits the package file: to
 * switch a package rule off, the host file carries an entry with the same id and
 * `enabled => false`. That is an explicit, greppable act that survives any
 * package update, and it needs neither a separate overrides map nor a
 * three-way merge.
 *
 * PHP format rather than JSON/YAML: `require` lands in opcache, PCRE is written
 * without double-escaping hell, pint and larastan see the file, and there are
 * no new dependencies.
 */
final class RuleRegistry
{
    /** Version of the file SCHEMA. A file with a newer one is not ours: we do not try to read it. */
    public const int SCHEMA_VERSION = 1;

    private static ?RuleSet $memo = null;

    /**
     * @param array<string, string|null>|null $files override the set of files
     *                                               (tests and `--validate`);
     *                                               the result is then NOT memoised
     */
    public static function load(bool $fresh = false, ?array $files = null): RuleSet
    {
        if ($files === null && !$fresh && self::$memo instanceof RuleSet) {
            return self::$memo;
        }

        $rules = [];
        $issues = [];
        $version = 'unknown';

        foreach ($files ?? self::files() as $source => $path) {
            if ($path === null || !is_file($path)) {
                continue;
            }

            [$fileRules, $fileIssues, $fileVersion] = self::loadFile($path, $source);

            // A later file overrides an earlier one PER id. array_merge is exactly
            // right here: the keys are string ids, so values are replaced, not appended.
            $rules = array_merge($rules, $fileRules);
            $issues = array_merge($issues, $fileIssues);

            if ($fileVersion !== null && $source === 'package') {
                $version = $fileVersion;
            }
        }

        $set = new RuleSet($rules, $issues, $version);

        // An overridden set of files never lands in the memo: otherwise one test
        // would poison the registry for every test after it.
        return $files === null ? self::$memo = $set : $set;
    }

    public static function flush(): void
    {
        self::$memo = null;
    }

    /**
     * Paths in ascending priority order.
     *
     * @return array<string, string|null>
     */
    public static function files(): array
    {
        $dir = dirname(__DIR__, 2).'/resources/heuristics';

        return [
            'package' => $dir.'/heuristics.php',
            'host' => self::hostFile(),
        ];
    }

    private static function hostFile(): ?string
    {
        // The host publishes its file into config/. `function_exists('config_path')`
        // does NOT help here, and that was verified: the function is declared in
        // the Laravel helpers and always exists once the framework is loaded, yet it
        // fails inside, on `Container::configPath()`, which the light container of
        // the pure test suite does not have. So the existence of the FUNCTION says
        // nothing about the existence of an APPLICATION. Hence the try/catch: outside
        // a full Laravel app there is simply no host file, and that is not an error.
        try {
            return config_path((string) config('security-scanner.heuristics_override', 'security-scanner-heuristics.php'));
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array{0: array<string, Rule>, 1: list<string>, 2: string|null}
     */
    private static function loadFile(string $path, string $source): array
    {
        $rules = [];
        $issues = [];

        try {
            /** @var mixed $payload */
            $payload = require $path;
        } catch (Throwable $e) {
            return [[], [sprintf('%s: the file failed to load - %s', $source, $e->getMessage())], null];
        }

        if (!is_array($payload)) {
            return [[], [sprintf('%s: the file must return an array', $source)], null];
        }

        $format = $payload['format'] ?? 0;

        if (!is_int($format) || $format > self::SCHEMA_VERSION) {
            return [[], [sprintf(
                '%s: format %s is newer than the supported %d - the whole file was skipped',
                $source,
                is_scalar($format) ? (string) $format : gettype($format),
                self::SCHEMA_VERSION,
            )], null];
        }

        $version = is_string($payload['version'] ?? null) ? $payload['version'] : null;
        $raw = $payload['rules'] ?? [];

        if (!is_array($raw)) {
            return [[], [sprintf('%s: rules must be a list', $source)], $version];
        }

        foreach ($raw as $entry) {
            if (!is_array($entry)) {
                $issues[] = sprintf('%s: a rule entry must be an array', $source);

                continue;
            }

            /** @var array<string, mixed> $entry */
            try {
                $rule = Rule::fromArray($entry, $source);
            } catch (InvalidSecurityRuleException $e) {
                // A broken rule is dropped; the rest of the set keeps working.
                $issues[] = sprintf('%s: %s', $source, $e->getMessage());

                continue;
            }

            if (isset($rules[$rule->id])) {
                $issues[] = sprintf('%s: duplicate id "%s" within one file', $source, $rule->id);
            }

            $rules[$rule->id] = $rule;
        }

        return [$rules, $issues, $version];
    }
}
