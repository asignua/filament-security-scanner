<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Matchers;

use Asignua\FilamentSecurityScanner\Scanning\Evidence;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;

/**
 * Extension or exact file name. Zero disk reads.
 *
 * Together with {@see PathMatcher}, this is the ONLY matcher type allowed to carry
 * `deterministic: true`, i.e. to enable auto-quarantine. The reason is that it
 * makes no probabilistic decision: "a file with a .php extension on a disk where
 * user uploads are stored" is a statement of fact, not a guess.
 * On 69,344 files of a media disk, the production check gave zero false positives.
 *
 * `chain: true` checks the WHOLE extension chain, not just the last one: this is how
 * `shell.php.jpg` is caught, which is served as an image but executed as PHP
 * on any server with `AddHandler` matching by partial name.
 */
final class ExtensionMatcher implements Matcher
{
    /**
     * @param list<string> $extensions lowercase, without the dot
     * @param list<string> $names      exact file names (`.htaccess`, `.user.ini`)
     */
    public function __construct(
        private readonly array $extensions = [],
        private readonly array $names = [],
        private readonly bool $chain = true,
    ) {}

    public static function type(): string
    {
        return 'extension';
    }

    public function needsContent(): bool
    {
        return false;
    }

    public function match(string $ruleId, MatchSubject $subject): array
    {
        $basename = strtolower($subject->basename);

        if (in_array($basename, array_map('strtolower', $this->names), true)) {
            return [Evidence::plain($ruleId, $subject->basename, ['reason' => 'filename'])];
        }

        if ($this->extensions === []) {
            return [];
        }

        // The case is already lowered in PathNormalizer: `shell.PHP` is executed by the same
        // php-fpm as `shell.php`, and the media disk already holds a file with "PNG".
        $candidates = $this->chain
            ? $subject->extensionChain
            : array_slice($subject->extensionChain, 0, 1);

        $hits = array_values(array_intersect($candidates, $this->extensions));

        if ($hits === []) {
            return [];
        }

        return [Evidence::plain($ruleId, $subject->basename, [
            'reason' => $hits[0] === ($subject->extensionChain[0] ?? null) ? 'extension' : 'extension-in-chain',
            'matched' => $hits[0],
            'chain' => implode('.', array_reverse($subject->extensionChain)),
        ])];
    }
}
