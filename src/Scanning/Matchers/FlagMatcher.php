<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Matchers;

use Asignua\FilamentSecurityScanner\Scanning\Evidence;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;

/**
 * A boolean attribute of the file itself, not of its content. So far there is one: symlink.
 *
 * A symlink in an upload zone means someone is taking reads/writes outside the
 * zone that is supposed to be confined to a directory. The scanner does NOT follow symlinks (otherwise it
 * would check the target instead of the fact itself), so the link must become
 * a finding right here.
 *
 * Although the check is deterministic, we do not enable `deterministic` for it:
 * a legitimate symlink in the tree is entirely possible (the same `public/storage`), and
 * the machine has no right to remove it.
 */
final class FlagMatcher implements Matcher
{
    public function __construct(private readonly string $flag) {}

    public static function type(): string
    {
        return 'flag';
    }

    /**
     * @return list<string>
     */
    public static function supported(): array
    {
        return ['symlink'];
    }

    public function needsContent(): bool
    {
        return false;
    }

    public function match(string $ruleId, MatchSubject $subject): array
    {
        $value = match ($this->flag) {
            'symlink' => $subject->isSymlink,
            default => false,
        };

        return $value
            ? [Evidence::plain($ruleId, $subject->path, ['flag' => $this->flag])]
            : [];
    }
}
