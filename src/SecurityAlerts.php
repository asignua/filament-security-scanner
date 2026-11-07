<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Filament\Resources\Security\SecurityResource;
use Asignua\FilamentSecurityScanner\Jobs\SendTelegramMessageJob;
use Asignua\FilamentSecurityScanner\Mail\SecurityFindingsReport;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Notifications\Notification;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Throwable;

/**
 * Single point for findings notifications. Three channels, one gate.
 *
 * THE GATE IS PER CHANNEL — per `notified_channels.<channel>` cell, not a shared
 * flag. The three channels fail in three different ways (SMTP is down / Telegram
 * returned 429 / the panel always works), and a single flag would give either
 * duplicates or silent losses. The stamp is set ONLY after this channel sent successfully.
 *
 * THRESHOLDS ARE PER CHANNEL: the panel gets everything, mail and Telegram only `high` and up.
 * A `low` finding has no right to wake anyone up.
 *
 * THROTTLING IS PER CHANNEL, once per `throttle_minutes`: an upload-triggered scan
 * can fire dozens of times an hour during a mass import, and without this an
 * editor who uploaded 200 files with one broken name would send 200
 * Telegram messages. Throttled findings stay `null` and roll into the
 * next batch — nothing is lost, only merged. The next batch is
 * driven by the hourly `security:notify` ({@see Schedule}): otherwise it would be the
 * next SCAN, and the delay would be measured in days, not `throttle_minutes`.
 *
 * Mail goes out SYNCHRONOUSLY (`sendNow()`), even though the mail is ShouldQueue: otherwise the stamp would be set
 * on queueing, not on sending.
 *
 * Telegram is an EXCEPTION to the stamp "synchronously in `channel()`": `toTelegram()` only
 * queues a job and returns `false`, so `channel()` stamps nothing here.
 * The stamp is set by `SendTelegramMessageJob::handle()` itself, and only
 * AFTER the Bot API confirmed receipt — a 429/timeout leaves the findings
 * unstamped, and the next batch picks them up again.
 *
 * No channel may break scanning: every send is wrapped in try/catch.
 */
final class SecurityAlerts
{
    public const array CHANNELS = ['database', 'mail', 'telegram'];

    /** How many characters of Telegram text the list takes — with a margin below 4096. */
    private const int TELEGRAM_BUDGET = 3900;

    /** Ceiling for one path in Telegram (before escaping). */
    private const int TELEGRAM_PATH_LENGTH = 120;

    /**
     * @return array<string, int> channel => how many findings were covered
     */
    public static function dispatch(bool $isFirstRun = false): array
    {
        $sent = [];

        foreach (self::CHANNELS as $channel) {
            try {
                $sent[$channel] = self::channel($channel, $isFirstRun);
            } catch (Throwable $e) {
                Log::warning(sprintf('Scanner notification (%s): %s', $channel, $e->getMessage()));
                $sent[$channel] = 0;
            }
        }

        return $sent;
    }

    private static function channel(string $channel, bool $isFirstRun): int
    {
        if (!self::channelEnabled($channel)) {
            return 0;
        }

        $findings = self::pending($channel);

        if ($findings->isEmpty()) {
            return 0;
        }

        if (self::throttled($channel)) {
            return 0;
        }

        $ok = match ($channel) {
            'database' => self::toPanel($findings, $isFirstRun),
            'mail' => self::toMail($findings, $isFirstRun),
            'telegram' => self::toTelegram($findings, $isFirstRun),
            default => false,
        };

        if (!$ok) {
            return 0;
        }

        self::stamp($findings, $channel);

        return $findings->count();
    }

    private static function channelEnabled(string $channel): bool
    {
        return match ($channel) {
            'database' => true,
            'mail' => is_string(self::mailRecipient()),
            'telegram' => Telegram::enabled(),
            default => false,
        };
    }

    public static function mailRecipient(): ?string
    {
        $recipient = config('security-scanner.notify.mail');

        // An empty config is itself the channel switch.
        return is_string($recipient) && filter_var($recipient, FILTER_VALIDATE_EMAIL) !== false
            ? $recipient
            : null;
    }

    /**
     * @return Collection<int, SecurityFinding>
     */
    private static function pending(string $channel): Collection
    {
        return SecurityFinding::query()
            ->notNotifiedVia($channel)
            ->where('severity_weight', '>=', self::minWeight($channel))
            ->orderByDesc('severity_weight')
            ->orderByDesc('last_seen_at')
            ->limit(200)
            ->get();
    }

    private static function minWeight(string $channel): int
    {
        /** @var array<string, string> $map */
        $map = (array) config('security-scanner.notify.min_severity', []);
        $name = is_string($map[$channel] ?? null) ? $map[$channel] : ($channel === 'database' ? 'low' : 'high');

        return (SecuritySeverity::tryFromName($name) ?? SecuritySeverity::High)->weight();
    }

    private static function throttled(string $channel): bool
    {
        $minutes = (int) config('security-scanner.notify.throttle_minutes', 60);

        if ($minutes <= 0) {
            return false;
        }

        // Cache::add is atomic: it returns false if the key already exists. One short
        // lock key with the site prefix is all the scanner keeps in the shared Redis.
        return !Cache::add('security-scanner.notify.'.$channel, 1, now()->addMinutes($minutes));
    }

    /**
     * Stamps `notified_channels.<channel>` on the given findings.
     *
     * Public: besides `channel()` (synchronous panel/mail), it is called by
     * `SendTelegramMessageJob::handle()` — asynchronously, only after a successful
     * send to Telegram (see the class docblock).
     *
     * @param Collection<int, SecurityFinding> $findings
     */
    public static function stamp(Collection $findings, string $channel): void
    {
        $now = now();

        foreach ($findings as $finding) {
            /** @var array<string, string|null> $channels */
            $channels = is_array($finding->notified_channels) ? $finding->notified_channels : [];
            $channels[$channel] = $now->toIso8601String();
            $finding->notified_channels = $channels;
            $finding->notified_at = $now;
            $finding->save();
        }
    }

    /**
     * @param Collection<int, SecurityFinding> $findings
     */
    private static function toPanel(Collection $findings, bool $isFirstRun): bool
    {
        // Who receives the in-panel notification is decided by the host: the package must not
        // demand its own role config for something the host already knows.
        $recipients = SecurityScanner::notifyUsers();

        if ($recipients->isEmpty()) {
            return false;
        }

        $top = $findings->first();
        $title = $isFirstRun
            ? __('security-scanner::ui.Security baseline inventory: :count findings', ['count' => $findings->count()])
            : __('security-scanner::ui.Security findings: :count new', ['count' => $findings->count()]);

        $notification = Notification::make()
            ->title($title)
            ->body($top instanceof SecurityFinding
                ? sprintf('%s — %s', SecurityPresenter::severityLabel($top->severity->value), (string) $top->path)
                : '')
            ->actions([
                Action::make('open')
                    ->label(__('security-scanner::ui.Open'))
                    ->url(self::panelUrl()),
            ]);

        $top instanceof SecurityFinding && $top->severity->weight() >= SecuritySeverity::High->weight()
            ? $notification->danger()
            : $notification->warning();

        foreach ($recipients as $user) {
            $notification->sendToDatabase($user);
        }

        return true;
    }

    /**
     * @param Collection<int, SecurityFinding> $findings
     */
    private static function toMail(Collection $findings, bool $isFirstRun): bool
    {
        $recipient = self::mailRecipient();

        if ($recipient === null) {
            return false;
        }

        // sendNow(), NOT send(): the mail is ShouldQueue, and send() would only queue
        // a job, after which the stamp would be set immediately. Without a queue worker or with an SMTP
        // failure in the job the alert was lost forever, and `security:notify` considered it
        // delivered. Synchronously the stamp is set only for a mail that was sent,
        // and an exception leaves the finding for the next batch. This adds no delay:
        // the SecurityScanFinished listener itself runs on the queue, and `security:notify` comes
        // from the schedule.
        Mail::to($recipient)->sendNow(new SecurityFindingsReport(
            findings: self::rows($findings),
            newCount: $findings->count(),
            totalCount: SecurityFinding::query()->open()->count(),
            panelUrl: self::panelUrl(),
            isFirstRun: $isFirstRun,
            siteName: (string) config('app.name', 'Laravel'),
        ));

        return true;
    }

    /**
     * @param Collection<int, SecurityFinding> $findings
     */
    private static function toTelegram(Collection $findings, bool $isFirstRun): bool
    {
        $lines = [];
        $lines[] = '<b>'.Telegram::escape((string) config('app.name', 'Laravel')).'</b> — '.Telegram::escape(
            $isFirstRun
                ? (string) __('security-scanner::ui.Security baseline inventory: :count findings', ['count' => $findings->count()])
                : (string) __('security-scanner::ui.Security findings: :count new', ['count' => $findings->count()]),
        );
        $lines[] = '';

        // The budget is counted BEFORE truncation, in whole lines: text cut in the middle of
        // `<code>` or `&amp;` is rejected by the Bot API (400), and the channel went silent.
        // The path is shortened BEFORE escaping (the column allows 400 characters, `&`
        // doubles), a line is added only while the whole text together with the tail
        // ("…and N more", link) stays within ~3900 characters.
        $footer = mb_strlen(Telegram::escape(self::panelUrl())) + 120;
        $budget = self::TELEGRAM_BUDGET - $footer - mb_strlen(implode("\n", $lines));
        $shown = [];

        foreach ($findings as $finding) {
            if (count($shown) >= 10) {
                break;
            }

            // The path goes in <code>: paths may contain `_` and `*`, which break Markdown —
            // hence HTML, and hence everything from the FS goes through escape().
            $line = sprintf(
                '%s %s: <code>%s</code>',
                self::marker($finding->severity),
                Telegram::escape(self::ruleLine($finding)),
                Telegram::escape(self::shortPath((string) $finding->path)),
            );

            $budget -= mb_strlen($line) + 1;

            if ($budget < 0) {
                break;
            }

            $lines[] = $line;
            $shown[] = $finding->id;
        }

        if ($findings->count() > count($shown)) {
            $lines[] = '';
            $lines[] = Telegram::escape((string) __('security-scanner::ui.…and :count more — see the panel', ['count' => $findings->count() - count($shown)]));
        }

        $lines[] = '';
        $lines[] = Telegram::escape(self::panelUrl());

        // Stamp only the SHOWN ones: the rest did not make it into the text and must go out in
        // the next batch rather than be considered notified.
        $findingIds = $shown;

        SendTelegramMessageJob::dispatch(implode("\n", $lines), $findingIds);

        // false on purpose: sending is asynchronous (a job in the queue), and the Bot API has
        // confirmed nothing yet. The job itself sets the stamp after success —
        // `channel()` must not (and cannot) know the result right now.
        return false;
    }

    /**
     * A path for Telegram — no longer than {@see TELEGRAM_PATH_LENGTH}: the beginning and
     * the end (file name) matter more than the middle.
     */
    private static function shortPath(string $path): string
    {
        if (mb_strlen($path) <= self::TELEGRAM_PATH_LENGTH) {
            return $path;
        }

        $half = intdiv(self::TELEGRAM_PATH_LENGTH - 1, 2);

        return mb_substr($path, 0, $half).'…'.mb_substr($path, -$half);
    }

    private static function marker(SecuritySeverity $severity): string
    {
        return match ($severity) {
            SecuritySeverity::Critical => '🔴',
            SecuritySeverity::High => '🟠',
            SecuritySeverity::Medium => '🟡',
            default => '⚪',
        };
    }

    /**
     * @param Collection<int, SecurityFinding> $findings
     *
     * @return list<array{severity: string, rule: string, path: string}>
     */
    private static function rows(Collection $findings): array
    {
        $rows = [];

        foreach ($findings as $f) {
            $rows[] = [
                'severity' => SecurityPresenter::severityLabel($f->severity->value),
                'rule' => self::ruleLine($f),
                'path' => (string) $f->path,
            ];
        }

        return $rows;
    }

    /**
     * The rule label for mail and Telegram. An auto-quarantined finding says
     * so directly: the recipient must know the machine has already removed the file — and that
     * it can be restored from the panel if it is a false positive.
     */
    private static function ruleLine(SecurityFinding $finding): string
    {
        $label = SecurityPresenter::ruleLabel($finding->rule_id, $finding->title);

        if ($finding->status === SecurityFindingStatus::Quarantined && $finding->quarantine_auto) {
            $label .= ' — '.__('security-scanner::ui.Auto-quarantined');
        }

        return $label;
    }

    public static function panelUrl(): string
    {
        try {
            // Panel-agnostic: the package does not know the host panel's ID, so it looks for
            // the one that registered this plugin.
            foreach (Filament::getPanels() as $panel) {
                if ($panel->hasPlugin('security-scanner')) {
                    return SecurityResource::getUrl('index', panel: $panel->getId());
                }
            }
        } catch (Throwable) {
            // Outside an HTTP context (worker, console) the panel router may not be
            // booted — then at least the home page rather than a failing notification.
        }

        return rtrim((string) config('app.url', ''), '/');
    }
}
