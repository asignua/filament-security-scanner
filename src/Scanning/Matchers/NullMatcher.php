<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Matchers;

use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;

/**
 * A matcher that never matches, and this is not a stub.
 *
 * Some findings the scanner detects ITSELF, not through a pattern match: divergence from
 * git, mismatch with the hash snapshot, a missing APP_KEY. But severity, signature and
 * allowlist for them must stay in the same registry as for the rest;
 * otherwise half of the thresholds would be tuned via data and half via a package release.
 *
 * So such rules declare `matcher.type = none`: the registry entry exists,
 * and the scanner does the detection. The alternative, pretending to match with a pattern such as `**`,
 * would be a lie in the data that the next reader would take for truth.
 *
 * Determinism is forbidden for such rules just as for regexes: the decision
 * to move someone else's file cannot rest on a conclusion reached bypassing the matcher.
 */
final class NullMatcher implements Matcher
{
    public static function type(): string
    {
        return 'none';
    }

    public function needsContent(): bool
    {
        return false;
    }

    public function match(string $ruleId, MatchSubject $subject): array
    {
        return [];
    }
}
