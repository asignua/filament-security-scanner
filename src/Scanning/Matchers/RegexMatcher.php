<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Matchers;

use Asignua\FilamentSecurityScanner\Scanning\Evidence;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;

/**
 * A pattern over file content; this is how all obfuscation heuristics are described.
 *
 * `deterministic: true` is FORBIDDEN for a matcher of this type by the registry validator
 * ({@see \Asignua\FilamentSecurityScanner\Scanning\RuleRegistry}). This is a structural guarantee, not an
 * agreement: auto-quarantine will never fire on a regex, no matter who writes what
 * in a rule, because the decision to move someone else's file cannot rest on a guess.
 *
 * Two safeguards, both from real experience:
 *
 * 1. A `preg_match` failure (catastrophic backtracking on a long file) is NOT considered
 *    "clean". The matcher returns evidence with `incomplete = true`, because silence and
 *    the absence of a threat are different things, and confusing them means silently going blind
 *    exactly on the largest files. The config validator does not catch this either: it runs
 *    `preg_match` over an EMPTY string, i.e. it checks syntax, not
 *    termination.
 * 2. `$subject->bytes === null` means "content was not read"; we return empty
 *    and assert nothing.
 */
final class RegexMatcher implements Matcher
{
    public function __construct(
        private readonly string $pattern,
        private readonly int $minMatches = 1,
    ) {}

    public static function type(): string
    {
        return 'regex';
    }

    public function needsContent(): bool
    {
        return true;
    }

    public function match(string $ruleId, MatchSubject $subject): array
    {
        if (!$subject->hasContent()) {
            return [];
        }

        $bytes = (string) $subject->bytes;
        $matches = [];

        $count = @preg_match_all($this->pattern, $bytes, $matches, PREG_OFFSET_CAPTURE);

        if ($count === false || preg_last_error() !== PREG_NO_ERROR) {
            return [Evidence::plain($ruleId, '[check did not complete]', [
                'incomplete' => true,
                'pcre_error' => preg_last_error_msg(),
                'bytes' => strlen($bytes),
            ])];
        }

        if ($count < $this->minMatches) {
            return [];
        }

        /** @var array<int, array{0: string, 1: int}> $first */
        $first = $matches[0];
        $evidence = [];

        // One evidence per rule, not per match: a shell with twenty occurrences of
        // `eval(` must not turn into twenty rows in the panel.
        [$needle, $offset] = $first[0];

        $evidence[] = Evidence::fromMatch($ruleId, $bytes, $offset, $needle, [
            'matches' => $count,
        ]);

        return $evidence;
    }
}
