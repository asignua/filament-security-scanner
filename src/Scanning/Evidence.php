<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

/**
 * One piece of evidence of a rule firing.
 *
 * The excerpt is truncated and escaped HERE, on input, not on display. The reason
 * is practical: these bytes were written by an attacker, and then they travel to the panel, a mail and
 * Telegram, three different places with three different escaping rules. The place
 * where it is easiest to make a mistake is the last one; so dangerous content must not
 * travel through the system in raw form at all.
 */
final readonly class Evidence
{
    /** How many characters of the excerpt we keep around the match. */
    public const int EXCERPT_LENGTH = 120;

    /**
     * @param array<string, scalar|null> $detail
     */
    public function __construct(
        public string $ruleId,
        public string $excerpt,
        public ?int $offset = null,
        public array $detail = [],
    ) {}

    /**
     * @param array<string, scalar|null> $detail
     */
    public static function fromMatch(string $ruleId, string $haystack, int $offset, string $needle, array $detail = []): self
    {
        $start = max(0, $offset - 20);
        $excerpt = substr($haystack, $start, self::EXCERPT_LENGTH);

        return new self(
            ruleId: $ruleId,
            excerpt: self::sanitize($excerpt),
            offset: $offset,
            detail: $detail + ['length' => strlen($needle)],
        );
    }

    /**
     * @param array<string, scalar|null> $detail
     */
    public static function plain(string $ruleId, string $excerpt, array $detail = []): self
    {
        return new self($ruleId, self::sanitize($excerpt), null, $detail);
    }

    /**
     * Printable ASCII is kept, the rest becomes `\xNN`.
     *
     * This is why an excerpt from a JPEG polyglot is readable in the panel instead of breaking the layout:
     * the binary "header" becomes a visible sequence rather than raw bytes that the
     * browser would try to interpret.
     */
    private static function sanitize(string $value): string
    {
        $out = '';

        foreach (str_split($value) as $char) {
            $code = ord($char);
            $out .= ($code >= 0x20 && $code <= 0x7E) || $char === "\n" || $char === "\t"
                ? $char
                : sprintf('\x%02X', $code);
        }

        return $out;
    }
}
