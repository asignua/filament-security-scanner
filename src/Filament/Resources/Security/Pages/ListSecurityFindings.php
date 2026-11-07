<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages;

use Asignua\FilamentSecurityScanner\Enums\SecurityScanTrigger;
use Asignua\FilamentSecurityScanner\Filament\Resources\Security\SecurityResource;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\SecurityPresenter;
use Filament\Resources\Pages\ListRecords;
use Illuminate\Support\Carbon;

class ListSecurityFindings extends ListRecords
{
    protected static string $resource = SecurityResource::class;

    /**
     * The state of the last run — here, not in a separate resource.
     *
     * This is the defence against the most dangerous failure mode: an empty list of
     * findings looks the same whether everything is clean or the scanner has not been working
     * for the fifth day. The subheading makes the difference visible without a single click.
     *
     * Only FULL runs (schedule, manual) — an upload spot check
     * sees one file, and a fresh upload-triggered run would otherwise hide that the nightly
     * scan has been dead for more than a day. We do not filter by status: a stuck `running` or
     * `failed` full run must be visible exactly here.
     */
    public function getSubheading(): ?string
    {
        $fullTriggers = array_values(array_map(
            static fn (SecurityScanTrigger $t): string => $t->value,
            array_filter(SecurityScanTrigger::cases(), static fn (SecurityScanTrigger $t): bool => $t->isFullCoverage()),
        ));

        $scan = SecurityScan::query()->whereIn('trigger', $fullTriggers)->latest('id')->first();

        if (!$scan instanceof SecurityScan) {
            return __('security-scanner::ui.The scanner has not run yet');
        }

        $when = $scan->finished_at ?? $scan->started_at ?? $scan->created_at;
        $status = SecurityPresenter::scanStatusLabel(
            $scan->status->value,
        );

        $line = sprintf(
            '%s: %s — %s',
            __('security-scanner::ui.Last scan'),
            $when instanceof Carbon ? $when->format('d.m.Y H:i') : '—',
            $status,
        );

        // A run stuck in `running` must be visible: that is exactly how a
        // scanner killed by OOM or a timeout looks.
        if ($when instanceof Carbon && $when->lt(now()->subDay())) {
            $line .= ' · '.__('security-scanner::ui.More than a day ago');
        }

        return $line;
    }
}
