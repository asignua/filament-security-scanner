<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Jobs;

use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\SecurityAlerts;
use Asignua\FilamentSecurityScanner\Telegram;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

/**
 * Sending to Telegram through the queue.
 *
 * The Bot API answers 429 on frequent calls; a retry with backoff in the queue
 * rides this out without blocking the sender. The message is a string, not a
 * model: a serialized finding might no longer exist by processing time.
 *
 * `findingIds` is optional: a test message from the host's button
 * carries no findings. When the list is non-empty, the `notified_channels.telegram` stamp
 * is set HERE, not in `SecurityAlerts::channel()` — precisely because the call
 * is asynchronous and may fail separately from the other channels.
 */
final class SendTelegramMessageJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public int $tries = 3;

    /** @var list<int> */
    public array $backoff = [10, 60, 300];

    /**
     * @param list<int> $findingIds
     */
    public function __construct(public readonly string $text, public readonly array $findingIds = []) {}

    public function handle(): void
    {
        if (!Telegram::send($this->text)) {
            // We do not throw: `false` means both "disabled" and "429". A retry makes sense only
            // for the latter, and they cannot be told apart here without duplicating the client.
            // The log was already written in Telegram::send(). The findings stay without
            // a stamp — the next SecurityAlerts::dispatch() batch will pick them up.
            return;
        }

        if ($this->findingIds === []) {
            return;
        }

        $findings = SecurityFinding::query()->whereIn('id', $this->findingIds)->get();

        SecurityAlerts::stamp($findings, 'telegram');
    }
}
