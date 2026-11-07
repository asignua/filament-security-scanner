<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Listeners;

use Asignua\FilamentSecurityScanner\Events\SecurityScanFinished;
use Asignua\FilamentSecurityScanner\SecurityAlerts;
use Illuminate\Contracts\Queue\ShouldQueue;

/**
 * Reacts to a run finishing: hands the work to the single notification gate.
 *
 * Queued, so the three channels (panel, mail, Telegram) neither lengthen the run itself
 * nor can break it. The gate does not rely on event data: it re-reads
 * from the DB the findings "new and not yet notified on this channel", so the event is
 * just a "take a look" signal, and nothing is lost if two runs finish
 * back to back.
 */
class NotifyAboutSecurityFindings implements ShouldQueue
{
    public int $tries = 2;

    public function handle(SecurityScanFinished $event): void
    {
        SecurityAlerts::dispatch(isFirstRun: $event->isFirstRun);
    }
}
