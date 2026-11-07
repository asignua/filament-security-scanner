<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Enums;

/**
 * What started the run. Without this it is impossible to tell a nightly full pass from
 * an instant check of a single just-uploaded file — and they have completely different
 * expectations about coverage and duration.
 */
enum SecurityScanTrigger: string
{
    /**
     * Schedule, full pass (04:40).
     */
    case Schedule = 'schedule';

    /**
     * The button on the "Tools" page or a console command.
     */
    case Manual = 'manual';

    /**
     * Reaction to a file upload into the media library — one target, not full coverage.
     */
    case Upload = 'upload';

    /**
     * Baseline snapshot at deploy.
     */
    case Deploy = 'deploy';

    /**
     * Whether a run of this kind covers the zones entirely. A targeted run after an upload
     * sees one file, so it has no right to close anything as `resolved`.
     */
    public function isFullCoverage(): bool
    {
        return $this === self::Schedule || $this === self::Manual;
    }

    public function labelKey(): string
    {
        return match ($this) {
            self::Schedule => 'security-scanner::ui.Scheduled',
            self::Manual => 'security-scanner::ui.Manual',
            self::Upload => 'security-scanner::ui.On upload',
            self::Deploy => 'security-scanner::ui.On deploy',
        };
    }

    public function label(): string
    {
        return (string) __($this->labelKey());
    }
}
