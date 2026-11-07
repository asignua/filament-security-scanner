<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Jobs;

use Asignua\FilamentSecurityScanner\Enums\SecurityScanStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityScanTrigger;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Scanning\ScanRunner;
use Asignua\FilamentSecurityScanner\SecurityScanner;
use Filament\Notifications\Notification;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Throwable;

/**
 * A full manual run of the intrusion-trace scanner — ONLY in the background.
 *
 * The motive is the pass duration: a real pass (a prod media disk holds tens of
 * thousands of files, plus hashing of the vendor zone) can take tens to hundreds of
 * seconds, while `max_execution_time` on prod is usually 30 s (fpm
 * `request_terminate_timeout` — 60 s). A synchronous call straight from the host's
 * button would die mid-run: the scans table row would stay with
 * status `running` FOREVER — no findings, no notification, and
 * it would look exactly like "all clean".
 *
 * The scanner list is deliberately NOT duplicated here: {@see ScanRunner::defaultScanners()}
 * is the ONE place, shared with the console command (`security:scan`).
 */
final class SecurityScanJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    /**
     * No retries on purpose: a repeated pass over the whole tree after a
     * partial failure costs as much as the first, and it is better to
     * start it deliberately.
     */
    public int $tries = 1;

    /**
     * One hour: the worker's default 60 s would kill the pass on any real
     * site. The host's "Scan" button must read the same threshold as the boundary of
     * "the run could still be executing", rather than its own number.
     */
    public const int TIMEOUT_SECONDS = 3600;

    public int $timeout = self::TIMEOUT_SECONDS;

    public function __construct(private readonly ?int $userId = null) {}

    public function handle(): void
    {
        if (!(bool) config('security-scanner.enabled', false)) {
            return;
        }

        // A crash mid-run must not stay silent —
        // the initiator must see "failed", not silence forever.
        try {
            $scan = (new ScanRunner(ScanRunner::defaultScanners()))->run(SecurityScanTrigger::Manual);
        } catch (Throwable $e) {
            $this->notify(
                Notification::make()
                    ->title(__('security-scanner::ui.Command failed'))
                    ->body($e->getMessage())
                    ->danger(),
            );

            throw $e;
        }

        $this->notify($this->finishedNotification($scan));
    }

    private function finishedNotification(SecurityScan $scan): Notification
    {
        $notification = Notification::make()
            ->title($scan->status->label())
            ->body(__('security-scanner::ui.Scan finished body', [
                'new' => $scan->findings_new,
                'total' => $scan->findings_total,
            ]));

        return match ($scan->status) {
            SecurityScanStatus::Findings => $notification->danger(),
            SecurityScanStatus::Partial => $notification->warning(),
            default => $notification->success(),
        };
    }

    /**
     * A database notification, not a toast: by completion time (up to an hour) the initiator
     * has long since reloaded the page. Without an initiator (schedule, console)
     * there is nobody to notify.
     */
    private function notify(Notification $notification): void
    {
        if ($this->userId === null) {
            return;
        }

        $model = SecurityScanner::userModel();
        $user = $model !== null ? $model::query()->find($this->userId) : null;

        if ($user !== null) {
            $notification->sendToDatabase($user);
        }
    }
}
