<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Illuminate\Console\Scheduling\Schedule as LaravelSchedule;

/**
 * The scanner schedule — registered by the package itself. A separate class so a test can pass a
 * fresh `new Schedule()` with the config it needs (the provider boots together with the
 * application, and `schedule.enabled` cannot be replaced before its boot()).
 */
final class Schedule
{
    public static function register(LaravelSchedule $schedule): void
    {
        if (!(bool) config('security-scanner.schedule.enabled', true)) {
            return;
        }

        // Synchronously, not via the queue: a dead worker must not be able to hide the
        // scanner. --fail-on=none: a non-zero exit code is useless in the scheduler.
        // withoutOverlapping — walking the disk can take minutes.
        $schedule->command('security:scan', ['--trigger' => 'schedule', '--fail-on' => 'none'])
            ->dailyAt((string) config('security-scanner.schedule.scan', '04:40'))
            ->withoutOverlapping(120);

        $schedule->command('security:prune')
            ->dailyAt((string) config('security-scanner.schedule.prune', '05:00'));

        // Re-sending throttled notifications: without this the "next batch" of
        // throttling is the next SCAN, i.e. a day, not throttle_minutes.
        // Laravel expects minute 0–59; an out-of-range config must not silently break the schedule.
        $minute = max(0, min(59, (int) config('security-scanner.schedule.notify_minute', 15)));
        $schedule->command('security:notify')
            ->hourlyAt($minute);
    }
}
