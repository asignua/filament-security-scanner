<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Enums;

/**
 * Finding lifecycle.
 *
 * `Resolved` and `Ignored` are DIFFERENT things, and must not be confused:
 *  - `Resolved` is set automatically when the condition disappeared (file removed, hash matches again);
 *  - `Ignored` is set by a human — "this is our file, stop asking", and it survives
 *    the same finding appearing again;
 *  - `Acknowledged` means only "seen", and the same content reappearing at
 *    the same path does not reset it (dedup relies on the fingerprint).
 *
 * Rotation cleans ONLY `Resolved` and `Ignored`: an unhandled intrusion has no right to
 * rot beyond the retention horizon (see {@see closesUnderRetention()}).
 */
enum SecurityFindingStatus: string
{
    case New = 'new';
    case Acknowledged = 'acknowledged';
    case Quarantined = 'quarantined';
    case Resolved = 'resolved';
    case Ignored = 'ignored';

    /**
     * Whether the finding still needs human attention.
     */
    public function isOpen(): bool
    {
        return $this === self::New || $this === self::Acknowledged;
    }

    /**
     * Whether rotation may delete such a row by age.
     * `New`/`Acknowledged`/`Quarantined` — never.
     */
    public function closesUnderRetention(): bool
    {
        return $this === self::Resolved || $this === self::Ignored;
    }

    /**
     * Whether to notify about a finding in this status. Only `New` — otherwise on the third
     * day nobody would read the mail and Telegram any more.
     */
    public function isNotifiable(): bool
    {
        return $this === self::New;
    }

    public function labelKey(): string
    {
        return match ($this) {
            self::New => 'security-scanner::ui.New',
            self::Acknowledged => 'security-scanner::ui.Acknowledged',
            self::Quarantined => 'security-scanner::ui.Quarantined',
            self::Resolved => 'security-scanner::ui.Resolved',
            self::Ignored => 'security-scanner::ui.Ignored',
        };
    }

    public function label(): string
    {
        return (string) __($this->labelKey());
    }

    public function color(): string
    {
        return match ($this) {
            self::New => 'danger',
            self::Acknowledged => 'warning',
            self::Quarantined => 'info',
            self::Resolved => 'success',
            self::Ignored => 'gray',
        };
    }
}
