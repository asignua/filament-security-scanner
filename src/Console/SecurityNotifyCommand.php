<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Console;

use Asignua\FilamentSecurityScanner\SecurityAlerts;
use Illuminate\Console\Command;

/**
 * Re-sends notifications about scanner findings that have not yet gone out on their channel.
 *
 * By itself the {@see SecurityAlerts} gate fires only when a run finishes,
 * and throttling (`notify.throttle_minutes`) postpones findings "to the next batch".
 * Without this command the next batch is the next RUN: scheduled at 04:40 or
 * when someone uploads a file, i.e. a throttled high-level finding could
 * wait a whole day. An hourly run in the schedule reduces the delay to the throttling
 * window itself. Cheap: one query per channel while there is nothing to send.
 */
class SecurityNotifyCommand extends Command
{
    protected $signature = 'security:notify';

    protected $description = 'Re-send not yet sent scanner finding notifications (panel / mail / Telegram)';

    public function handle(): int
    {
        $sent = SecurityAlerts::dispatch();

        // Telegram is always 0: the job is queued, and it stamps the findings itself
        // after the Bot API responds (see the SecurityAlerts docblock).
        $this->info(sprintf(
            'Notified: panel %d, mail %d, Telegram (queued) %d.',
            $sent['database'] ?? 0,
            $sent['mail'] ?? 0,
            $sent['telegram'] ?? 0,
        ));

        return self::SUCCESS;
    }
}
