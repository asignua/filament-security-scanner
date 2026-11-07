<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Enums;

/**
 * Severity of an intrusion-trace scanner finding.
 *
 * There are two representations of the level ON PURPOSE: the string goes into `security_findings.severity`
 * for humans, the number into `severity_weight` for SQL. `WHERE severity_weight >= 60`
 * can use an index, `WHERE severity IN ('critical','high')` cannot. The same trick
 * as in {@see Role::weight()}.
 *
 * Notification thresholds are set exactly by weight (`security-scanner.notify.min_severity.*`),
 * so a new level between the existing ones can be added without rewriting site configs —
 * the weights leave a gap of 20 between them.
 */
enum SecuritySeverity: string
{
    /**
     * Confirmed executable junk where it cannot be. Wakes people at night.
     */
    case Critical = 'critical';

    /**
     * A strong signal that requires investigation the same day.
     */
    case High = 'high';

    /**
     * An anomaly that may be legitimate. Reviewed on a regular basis.
     */
    case Medium = 'medium';

    /**
     * A trifle or expected drift (composer removed a file).
     */
    case Low = 'low';

    /**
     * Not a problem but a fact: "the file is too large, its contents were not read".
     */
    case Info = 'info';

    public function weight(): int
    {
        return match ($this) {
            self::Critical => 100,
            self::High => 80,
            self::Medium => 60,
            self::Low => 40,
            self::Info => 20,
        };
    }

    public function labelKey(): string
    {
        return match ($this) {
            self::Critical => 'security-scanner::ui.Critical',
            self::High => 'security-scanner::ui.High',
            self::Medium => 'security-scanner::ui.Medium',
            self::Low => 'security-scanner::ui.Low',
            self::Info => 'security-scanner::ui.Info',
        };
    }

    public function label(): string
    {
        return (string) __($this->labelKey());
    }

    /**
     * Badge color in Filament.
     */
    public function color(): string
    {
        return match ($this) {
            self::Critical => 'danger',
            self::High => 'warning',
            self::Medium => 'info',
            self::Low => 'gray',
            self::Info => 'gray',
        };
    }

    /**
     * Parsing a value from the heuristics registry. An unknown level does NOT crash the loader —
     * the rule is rejected by the validator with a `hygiene.registry-rule-invalid` finding,
     * because a broken host rules file has no right to take down the whole scanner.
     */
    public static function tryFromName(?string $value): ?self
    {
        return $value === null ? null : self::tryFrom(strtolower($value));
    }

    /**
     * Levels with weight not lower than the threshold — for notification gates.
     *
     * @return list<self>
     */
    public static function atLeast(self $threshold): array
    {
        return array_values(array_filter(
            self::cases(),
            static fn (self $s): bool => $s->weight() >= $threshold->weight(),
        ));
    }
}
