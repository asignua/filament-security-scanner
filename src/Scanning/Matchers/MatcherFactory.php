<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Matchers;

use Asignua\FilamentSecurityScanner\Scanning\Exceptions\InvalidSecurityRuleException;

/**
 * Builds a matcher from a registry entry and validates it RIGHT THERE.
 *
 * Validation lives in the factory, not in the scanner, on purpose: a rule that cannot be
 * built must not survive until the filesystem walk. Broken rule data is rejected once at load time, not a million times on
 * every file.
 */
final class MatcherFactory
{
    /**
     * @return list<string>
     */
    public static function types(): array
    {
        return [
            ExtensionMatcher::type(),
            PathMatcher::type(),
            RegexMatcher::type(),
            FlagMatcher::type(),
            NullMatcher::type(),
        ];
    }

    /**
     * Types allowed to carry `deterministic: true`.
     *
     * This is the structural guarantee of auto-quarantine: the decision to move someone else's file
     * rests only on fact (extension, path), never on a guess (regex).
     *
     * @return list<string>
     */
    public static function deterministicTypes(): array
    {
        return [ExtensionMatcher::type(), PathMatcher::type()];
    }

    /**
     * @param array<string, mixed> $config
     *
     * @throws InvalidSecurityRuleException
     */
    public static function make(string $ruleId, array $config): Matcher
    {
        $type = $config['type'] ?? null;

        if (!is_string($type) || $type === '') {
            throw new InvalidSecurityRuleException($ruleId, 'matcher.type is not specified');
        }

        return match ($type) {
            ExtensionMatcher::type() => self::extension($ruleId, $config),
            PathMatcher::type() => self::path($ruleId, $config),
            RegexMatcher::type() => self::regex($ruleId, $config),
            FlagMatcher::type() => self::flag($ruleId, $config),
            NullMatcher::type() => new NullMatcher,
            default => throw new InvalidSecurityRuleException(
                $ruleId,
                sprintf('unknown matcher.type "%s" (known: %s)', $type, implode(', ', self::types())),
            ),
        };
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function extension(string $ruleId, array $config): ExtensionMatcher
    {
        $extensions = self::stringList($ruleId, $config, 'extensions');
        $names = self::stringList($ruleId, $config, 'names');

        if ($extensions === [] && $names === []) {
            throw new InvalidSecurityRuleException($ruleId, 'matcher.extensions and matcher.names are both empty');
        }

        return new ExtensionMatcher(
            extensions: array_map('strtolower', $extensions),
            names: $names,
            chain: (bool) ($config['chain'] ?? true),
        );
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function path(string $ruleId, array $config): PathMatcher
    {
        $patterns = self::stringList($ruleId, $config, 'patterns');

        if ($patterns === []) {
            throw new InvalidSecurityRuleException($ruleId, 'matcher.patterns is empty');
        }

        return new PathMatcher($patterns, self::stringList($ruleId, $config, 'except'));
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function regex(string $ruleId, array $config): RegexMatcher
    {
        $pattern = $config['pattern'] ?? null;

        if (!is_string($pattern) || $pattern === '') {
            throw new InvalidSecurityRuleException($ruleId, 'matcher.pattern is not specified');
        }

        // Compiled here, not on the first file: otherwise a broken regex from
        // a rules file would surface at 04:40 in the middle of the nightly pass.
        if (@preg_match($pattern, '') === false) {
            throw new InvalidSecurityRuleException(
                $ruleId,
                sprintf('matcher.pattern does not compile: %s', preg_last_error_msg()),
            );
        }

        $min = $config['min_matches'] ?? 1;

        if (!is_int($min) || $min < 1) {
            throw new InvalidSecurityRuleException($ruleId, 'matcher.min_matches must be an integer >= 1');
        }

        return new RegexMatcher($pattern, $min);
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function flag(string $ruleId, array $config): FlagMatcher
    {
        $flag = $config['flag'] ?? null;

        if (!is_string($flag) || !in_array($flag, FlagMatcher::supported(), true)) {
            throw new InvalidSecurityRuleException(
                $ruleId,
                sprintf('matcher.flag must be one of: %s', implode(', ', FlagMatcher::supported())),
            );
        }

        return new FlagMatcher($flag);
    }

    /**
     * @param array<string, mixed> $config
     *
     * @throws InvalidSecurityRuleException
     *
     * @return list<string>
     */
    private static function stringList(string $ruleId, array $config, string $key): array
    {
        $value = $config[$key] ?? [];

        if (!is_array($value)) {
            throw new InvalidSecurityRuleException($ruleId, sprintf('matcher.%s must be a list of strings', $key));
        }

        foreach ($value as $item) {
            if (!is_string($item)) {
                throw new InvalidSecurityRuleException($ruleId, sprintf('matcher.%s contains a non-string', $key));
            }
        }

        /** @var list<string> */
        return array_values($value);
    }
}
