<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Jobs\SecurityScanPathJob;
use Illuminate\Support\Facades\Log;
use Spatie\MediaLibrary\MediaCollections\Events\MediaHasBeenAddedEvent;
use Spatie\MediaLibrary\MediaCollections\Models\Media;
use Throwable;

/**
 * Reaction to an upload into the media library.
 *
 * HOOKED UP ONLY WHEN spatie/laravel-medialibrary IS INSTALLED:
 * `MediaHasBeenAddedEvent` is a soft dependency (composer `suggest`, not
 * `require`): the provider registers the listener only when the event class exists
 * (`class_exists()`), so the package stays functional without the media library.
 *
 * SYNCHRONOUSLY, only what costs one stat and one fread: extension against
 * executable ones, double extension, magic of the first bytes against the extension. Within a
 * strict budget `upload.sync_budget_ms`; exceeding it is logged once and
 * aborts the check. THE UPLOAD ALWAYS WINS: a scanner error must not be allowed to give
 * a 500 on upload, so everything is in try/catch.
 *
 * ASYNCHRONOUSLY, a full pass over this one file (SecurityScanPathJob), which
 * both creates the finding and, if allowed, quarantines it.
 *
 * THE HOOK POINT is the MediaHasBeenAddedEvent event, NOT the Eloquent `created` event.
 * Verified by tracing: at the moment of `created` the file is not on disk yet; spatie
 * first creates the row and copies the file AFTER (Filesystem::add), and the event
 * fires only after copying. An observer on `created` saw an empty place and
 * honestly stayed silent, i.e. it reacted to nothing.
 *
 * A DELIBERATE LIMITATION: the event comes AFTER the write, so this is "the upload succeeded for a moment and
 * was revoked", not blocking. But an executable EXTENSION is rejected by the media library
 * itself, before the write (FileAdder::$defaultDisallowedExtensions), so the
 * real value of this class is in checking CONTENT: polyglots and PHP disguised as
 * an image, which the extension does not reveal.
 */
final class MediaUploadScanObserver
{
    private const array EXECUTABLE = [
        'php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
        'phtml', 'pht', 'phar', 'phps', 'inc', 'shtml', 'cgi', 'pl', 'py', 'sh',
    ];

    /**
     * Magic of the formats PHP is hidden in. Kept in sync with the rule
     * `obf.php-after-binary` (resources/heuristics/heuristics.php).
     */
    private const string IMAGE_MAGIC = '~\A(?:\xff\xd8\xff|\x89PNG|GIF8|%PDF|RIFF[\s\S]{4}WEBP|[\s\S]{4}ftyp(?:avif|avis|heic|heix|mif1))~';

    public function handle(MediaHasBeenAddedEvent $event): void
    {
        $this->inspect($event->media);
    }

    public function inspect(Media $media): void
    {
        if (!(bool) config('security-scanner.enabled', false)
            || !(bool) config('security-scanner.upload.enabled', true)) {
            return;
        }

        try {
            $absolute = $media->getPath();
        } catch (Throwable) {
            // Non-local disk (S3): there is no path, nothing to look at synchronously.
            return;
        }

        if ($absolute === '' || !is_file($absolute)) {
            return;
        }

        $relative = PathNormalizer::relative($absolute, Zones::base());
        $started = hrtime(true);

        try {
            $suspicious = $this->quickCheck($absolute, $relative, $started);
        } catch (Throwable $e) {
            Log::warning('Upload check: '.$e->getMessage(), ['path' => $relative]);
            $suspicious = true;    // a check error is a reason to look, not a reason to stay silent
        }

        // The full pass goes to the queue, and ONLY when there is something to look at: queuing a job
        // for each of the thousands of images in a bulk import would clog the queue
        // with runs that find nothing.
        if ($suspicious) {
            SecurityScanPathJob::dispatch($relative);
        }
    }

    /**
     * Three cheap checks in order of increasing cost. `true` = suspicious.
     */
    private function quickCheck(string $absolute, string $relative, int $startedNs): bool
    {
        $chain = PathNormalizer::extensionChain($relative);

        // 1. Extension: zero IO.
        if (array_intersect($chain, self::EXECUTABLE) !== []) {
            return true;
        }

        if ($this->overBudget($startedNs)) {
            return false;
        }

        // 2. Magic against extension: one fread.
        $sniff = (int) config('security-scanner.upload.sniff_bytes', 4096);
        $handle = @fopen($absolute, 'rb');

        if ($handle === false) {
            return true;
        }

        $head = (string) fread($handle, max(16, $sniff));
        fclose($handle);

        $ext = $chain[0] ?? '';

        // An image that starts with <?php is not an image.
        if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg', 'pdf'], true)
            && preg_match('~\A\s*<\?(?:php|=)~i', $head) === 1) {
            return true;
        }

        // 3. Polyglot: genuine image magic AND a PHP tag in the first bytes.
        // The same variants as in the obf.php-after-binary rule: the tag is
        // case-insensitive, `<?=` always works, magic covers webp/avif too.
        // Here `<?=` with no PHP marker next to it is deliberately enough: a false positive
        // costs only a job, and the full pass will decide by the rule.
        if (preg_match(self::IMAGE_MAGIC, $head) === 1
            && preg_match('~<\?(?:php|=)~i', $head) === 1) {
            return true;
        }

        return false;
    }

    private function overBudget(int $startedNs): bool
    {
        $budgetMs = (int) config('security-scanner.upload.sync_budget_ms', 150);

        if ($budgetMs <= 0) {
            return false;
        }

        if ((hrtime(true) - $startedNs) / 1_000_000 <= $budgetMs) {
            return false;
        }

        Log::info('Upload check exceeded the budget; aborted', ['budget_ms' => $budgetMs]);

        return true;
    }
}
