<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * A thin Telegram Bot API client — exactly one method.
 *
 * Why NOT a Laravel Notification channel: there is no notifiable entity here.
 * The recipient is the `chat_id` from config, not a User with routing. A channel for a single
 * chat_id would be an abstraction with no second use. Do not "fix" this.
 *
 * The token and chat_id come from ENV, not from Settings: they are credentials, and Settings values
 * are visible to every Admin in the panel and end up in the activity log diff. One place for
 * rotation.
 *
 * Never throws outward: a notification has no right to break what it
 * notifies about. An error goes to the log and `false`.
 */
final class Telegram
{
    public const int MAX_LENGTH = 4096;

    public static function enabled(): bool
    {
        return (bool) config('security-scanner.telegram.enabled', false)
            && self::token() !== ''
            && self::chatId() !== '';
    }

    public static function token(): string
    {
        return trim((string) config('security-scanner.telegram.token', ''));
    }

    public static function chatId(): string
    {
        return trim((string) config('security-scanner.telegram.chat_id', ''));
    }

    /**
     * @param 'HTML'|'MarkdownV2'|null $parseMode
     */
    public static function send(string $text, ?string $parseMode = 'HTML'): bool
    {
        if (!self::enabled()) {
            return false;
        }

        $text = self::fit($text);

        try {
            $response = Http::timeout((int) config('security-scanner.telegram.timeout', 5))
                ->post(sprintf('https://api.telegram.org/bot%s/sendMessage', self::token()), array_filter([
                    'chat_id' => self::chatId(),
                    'text' => $text,
                    'parse_mode' => $parseMode,
                    'disable_web_page_preview' => true,
                ]));

            if (!$response->successful()) {
                logger()->warning('Telegram: failed to send the message', [
                    'status' => $response->status(),
                    'body' => mb_substr($response->body(), 0, 300),
                ]);

                return false;
            }

            return true;
        } catch (Throwable $e) {
            logger()->warning('Telegram: '.self::redact($e->getMessage()));

            return false;
        }
    }

    /**
     * Guzzle puts the request URL, which carries `/bot<token>/`, into its exception
     * messages. The token is a credential: it must not reach logs or error trackers.
     */
    public static function redact(string $message): string
    {
        $message = (string) preg_replace('~/bot[^/\s]+/~', '/bot<redacted>/', $message);
        $token = self::token();

        return $token === '' ? $message : str_replace($token, '<redacted>', $message);
    }

    /**
     * The Bot API ceiling is 4096 characters per message. We truncate HONESTLY, with a
     * marker, not silently: a truncated findings list without a marker would look
     * complete.
     *
     * And ON A LINE BOUNDARY, not in the middle: the text here is already HTML-escaped, and truncating
     * inside `<code>` or `&amp;` gives 400 "can't parse entities". The same
     * text would be rebuilt and rejected every hour — the channel went silent forever. A line
     * with no line break within the limit (one giant line) is cut by
     * character, but we roll back to the last `<` or `&` so as not to leave
     * a broken tag or entity.
     */
    public static function fit(string $text): string
    {
        if (mb_strlen($text) <= self::MAX_LENGTH) {
            return $text;
        }

        $cut = mb_substr($text, 0, self::MAX_LENGTH - 2);
        $newline = mb_strrpos($cut, "\n");

        if ($newline !== false && $newline > 0) {
            return rtrim(mb_substr($cut, 0, $newline)).("\n").'…';
        }

        $markup = max((int) mb_strrpos($cut, '<'), (int) mb_strrpos($cut, '&'));

        return ($markup > 0 ? mb_substr($cut, 0, $markup) : $cut).'…';
    }

    /**
     * Escaping for parse_mode=HTML. Everything that came from the FS (file names!)
     * must pass through here — otherwise `<script>.php` breaks the markup and, in the worst
     * case, passes itself off as a tag.
     */
    public static function escape(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
