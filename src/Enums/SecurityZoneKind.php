<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Enums;

/**
 * The KIND of a file system zone — not the zone itself.
 *
 * This is the seam that keeps heuristics portable between sites: a rule
 * declares `applies_to => ['upload:web']`, not "storage/app/public". A rule does not
 * know and must not know the disk names of a particular site; concrete paths live in
 * `config('security-scanner.zones')`.
 *
 * The `UploadWeb` / `UploadPrivate` distinction is not pedantry but the auto-quarantine boundary:
 * the machine may move a file by itself ONLY in a zone reachable through the webroot (that is where
 * the executable shells lay on 20.09.2026). A private media disk is served only through
 * PHP, so a `.php` there is a finding, but not a reason to touch the file without a human.
 */
enum SecurityZoneKind: string
{
    /**
     * public/ — the root served by nginx. PHP is allowed here only as index.php.
     */
    case Webroot = 'webroot';

    /**
     * Written by the application AND reachable through the webroot. The hot zone.
     */
    case UploadWeb = 'upload:web';

    /**
     * Written by the application, served only through PHP (media, video).
     */
    case UploadPrivate = 'upload:private';

    /**
     * Application code — expected to stay unchanged between deploys.
     */
    case Code = 'code';

    /**
     * vendor/ — rebuilt by composer on every deploy.
     */
    case Vendor = 'vendor';

    /**
     * Whether this is a user-uploads zone (either kind).
     */
    public function isUploadZone(): bool
    {
        return $this === self::UploadWeb || $this === self::UploadPrivate;
    }

    /**
     * Whether the machine is allowed to quarantine a file ITSELF in a zone of this kind.
     *
     * Condition 4 of eight in {@see \Asignua\FilamentSecurityScanner\Scanning\Quarantine::mayAutoQuarantine()}.
     * The default is deliberately narrow: a mistake in `code` takes a site down, a mistake in `upload:web`
     * takes away a picture that is visible in quarantine and can be restored.
     */
    public function allowsAutoQuarantine(): bool
    {
        /** @var list<string> $allowed */
        $allowed = (array) config('security-scanner.quarantine.auto_zones', [self::UploadWeb->value]);

        return in_array($this->value, $allowed, true);
    }

    /**
     * Whether a HUMAN is allowed to quarantine this finding's file with a panel button.
     *
     * Narrowed to upload zones on purpose: moving a file out of the webroot/code/
     * vendor takes a site down, and a human makes such a decision with a deploy or
     * a manual deletion, not with a button in the findings list. Auto-quarantine is already
     * narrowed the same way in {@see allowsAutoQuarantine()} — this is the same boundary for
     * the manual path.
     */
    public function allowsManualQuarantine(): bool
    {
        return $this->isUploadZone();
    }

    public function labelKey(): string
    {
        return match ($this) {
            self::Webroot => 'security-scanner::ui.Web root',
            self::UploadWeb => 'security-scanner::ui.Public uploads',
            self::UploadPrivate => 'security-scanner::ui.Private uploads',
            self::Code => 'security-scanner::ui.Application code',
            self::Vendor => 'security-scanner::ui.Dependencies',
        };
    }

    public function label(): string
    {
        return (string) __($this->labelKey());
    }
}
