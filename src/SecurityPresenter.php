<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityScanStatus;
use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Scanning\PathNormalizer;
use Asignua\FilamentSecurityScanner\Scanning\RuleRegistry;

/**
 * Labels and colors for the panel.
 *
 * A separate class rather than methods on the model: the same thing has to be shown in
 * the table, the infolist, the mail and Telegram — four places with different
 * escaping rules. One source of labels is cheaper than four copies that
 * would drift apart.
 *
 * Values lie in the DB as strings, so all methods accept `?string` and tolerate
 * unknown ones: a rule may have been removed from the registry after the finding
 * was recorded, and the panel must not fail because of that.
 */
final class SecurityPresenter
{
    public static function severityLabel(?string $value): string
    {
        return SecuritySeverity::tryFromName($value)?->label() ?? ($value ?? '—');
    }

    public static function severityColor(?string $value): string
    {
        return SecuritySeverity::tryFromName($value)?->color() ?? 'gray';
    }

    public static function statusLabel(?string $value): string
    {
        return $value === null ? '—' : (SecurityFindingStatus::tryFrom($value)?->label() ?? $value);
    }

    public static function statusColor(?string $value): string
    {
        return $value === null ? 'gray' : (SecurityFindingStatus::tryFrom($value)?->color() ?? 'gray');
    }

    public static function scanStatusLabel(?string $value): string
    {
        return $value === null ? '—' : (SecurityScanStatus::tryFrom($value)?->label() ?? $value);
    }

    public static function scanStatusColor(?string $value): string
    {
        return $value === null ? 'gray' : (SecurityScanStatus::tryFrom($value)?->color() ?? 'gray');
    }

    /**
     * Text for a cell of the stock mail's markdown table.
     *
     * File names are written by the attacker, and `{{ }}` escapes HTML, not markdown: a backtick
     * closed the code span, `|` shifted the columns, a line break added arbitrary
     * markdown — a clickable link appeared in the admin's mail. Control bytes
     * (including line breaks) become `\xNN`, markdown syntax is escaped with `\`. `<`, `>`, `&`
     * are NOT touched: Blade escapes them, and `\&` in CommonMark would show the entity
     * literally.
     */
    public static function markdownText(string $value): string
    {
        return (string) preg_replace('/([\\\\`*_{}\[\]()#+\-.!|~])/', '\\\\$1', PathNormalizer::escapeBytes($value));
    }

    /**
     * Human-readable rule label.
     *
     * First — what was recorded AT THE MOMENT of the finding (the `title` column): the list must not
     * re-render from the registry, which may have changed since, otherwise
     * history would start showing today's wording for yesterday's events.
     * The registry is only a fallback for old rows without a title.
     *
     * `title` holds a translation KEY (prefixed `security-scanner::rules.`), and it is
     * translated HERE, at render time — not in the scanner. Otherwise the name
     * would freeze in the language of the scanner process (cron, queue). Old rows with already
     * translated text (not a key) are returned unchanged by `__()`.
     */
    public static function ruleLabel(?string $ruleId, ?string $storedTitle = null): string
    {
        $message = $ruleId === null ? null : RuleRegistry::load()->get($ruleId)?->message;

        if (is_string($storedTitle) && $storedTitle !== '') {
            $label = (string) __($storedTitle);

            // A key that did not resolve (the string came back as is) is typically a legacy
            // key from the previous host-integrated version of the scanner, or a key the host has not
            // synced yet. Then today's rule message from the
            // registry is better than a raw key in the table; if the registry is silent too —
            // keep the stored value.
            if ($label === $storedTitle && self::looksLikeKey($storedTitle) && $message !== null && $message !== '') {
                return (string) __($message);
            }

            return $label;
        }

        if ($ruleId === null) {
            return '—';
        }

        return $message !== null && $message !== '' ? (string) __($message) : $ruleId;
    }

    /**
     * A translation key, not human text: a `x::` namespace or an `ee.` prefix
     * (the title format of the previous host-integrated version of the scanner).
     */
    private static function looksLikeKey(string $value): bool
    {
        return str_contains($value, '::') || str_starts_with($value, 'ee.');
    }

    /**
     * Scanner labels. Keys are the same strings as in Rule::SCANNERS.
     *
     * @return array<string, string>
     */
    public static function scannerOptions(): array
    {
        return [
            'uploads' => (string) __('security-scanner::ui.Upload zones'),
            'code' => (string) __('security-scanner::ui.Code integrity'),
            'obfuscation' => (string) __('security-scanner::ui.Obfuscation'),
            'hygiene' => (string) __('security-scanner::ui.Environment hygiene'),
        ];
    }

    public static function scannerLabel(?string $value): string
    {
        return $value === null ? '—' : (self::scannerOptions()[$value] ?? $value);
    }

    /**
     * @return array<string, string>
     */
    public static function severityOptions(): array
    {
        $out = [];

        foreach (SecuritySeverity::cases() as $case) {
            $out[$case->value] = $case->label();
        }

        return $out;
    }

    /**
     * @return array<string, string>
     */
    public static function statusOptions(): array
    {
        $out = [];

        foreach (SecurityFindingStatus::cases() as $case) {
            $out[$case->value] = $case->label();
        }

        return $out;
    }
}
