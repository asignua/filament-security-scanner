<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Enums;

/**
 * Scanner run result.
 *
 * `Running` is written AT THE START, not at the end: a run killed by OOM or a timeout
 * must leave a trace. A scanner that silently did not run looks exactly like "all
 * clean" — and that is the most dangerous failure mode of the whole subsystem.
 *
 * `Partial` is a separate status, not a kind of `Ok`, because a protective invariant rests on it:
 * a run that exhausted its budget MUST NOT move old
 * findings to `resolved` ({@see closesFindings()}). Otherwise a timeout quietly closes
 * a real intrusion.
 */
enum SecurityScanStatus: string
{
    case Running = 'running';
    case Ok = 'ok';
    case Findings = 'findings';
    case Partial = 'partial';
    case Failed = 'failed';

    /**
     * Whether the run covered the zones fully enough that unseen findings can be
     * considered gone. Full passes only.
     */
    public function closesFindings(): bool
    {
        return $this === self::Ok || $this === self::Findings;
    }

    public function isFinished(): bool
    {
        return $this !== self::Running;
    }

    public function labelKey(): string
    {
        return match ($this) {
            self::Running => 'security-scanner::ui.Running',
            self::Ok => 'security-scanner::ui.Clean',
            self::Findings => 'security-scanner::ui.Findings detected',
            self::Partial => 'security-scanner::ui.Partial scan',
            self::Failed => 'security-scanner::ui.Failed',
        };
    }

    public function label(): string
    {
        return (string) __($this->labelKey());
    }

    public function color(): string
    {
        return match ($this) {
            self::Running => 'gray',
            self::Ok => 'success',
            self::Findings => 'danger',
            self::Partial => 'warning',
            self::Failed => 'danger',
        };
    }
}
