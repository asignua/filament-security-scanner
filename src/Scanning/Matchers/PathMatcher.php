<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Matchers;

use Asignua\FilamentSecurityScanner\Scanning\Evidence;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;
use Asignua\FilamentSecurityScanner\Scanning\PathNormalizer;

/**
 * Match of a path against a glob pattern. Zero disk reads.
 *
 * Needed for rules of the form "this directory must contain nothing but the listed" —
 * for example, the only allowed `.php` in the webroot is `public/index.php`.
 * Patterns go through {@see PathNormalizer::matchesGlob()}, where `*` does not cross
 * "/" and `**` does: without this distinction an entry like `public/*` would silently
 * cover the whole subtree.
 */
final class PathMatcher implements Matcher
{
    /**
     * @param list<string> $patterns
     * @param list<string> $except     exception paths that are NOT considered a match (always case-sensitive)
     * @param bool         $ignoreCase whether the PATTERNS ignore case (`shell.PHP`)
     */
    public function __construct(
        private readonly array $patterns,
        private readonly array $except = [],
        private readonly bool $ignoreCase = false,
    ) {}

    public static function type(): string
    {
        return 'path';
    }

    public function needsContent(): bool
    {
        return false;
    }

    public function match(string $ruleId, MatchSubject $subject): array
    {
        foreach ($this->except as $pattern) {
            if (PathNormalizer::matchesGlob($subject->path, $pattern)) {
                return [];
            }
        }

        foreach ($this->patterns as $pattern) {
            if (PathNormalizer::matchesGlob($subject->path, $pattern, $this->ignoreCase)) {
                return [Evidence::plain($ruleId, $subject->path, ['pattern' => $pattern])];
            }
        }

        return [];
    }
}
