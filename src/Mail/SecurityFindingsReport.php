<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

/**
 * A mail to the administrator about new scanner findings.
 *
 * THE BODY CONTAINS NO FILE CONTENTS — only the path, rule, severity and a link to
 * the panel. Evidence excerpts stay behind authorization: a mail quoting webshell code is itself
 * a leak.
 *
 * Scalars and arrays of scalars, not models: the host may queue the mail, and the
 * findings could have changed status before processing. The package itself sends it with `sendNow()`
 * ({@see \Asignua\FilamentSecurityScanner\SecurityAlerts}) — the notification stamp must
 * be set for a sent mail, not a queued one. The locale is the configured mail language
 * (`security-scanner.mail.locale`), otherwise the application language: the recipient is a
 * configured e-mail, not a user model with its own language.
 */
class SecurityFindingsReport extends Mailable implements ShouldQueue
{
    use Queueable;
    use SerializesModels;

    /**
     * @param list<array{severity: string, rule: string, path: string}> $findings
     */
    public function __construct(
        public array $findings,
        public int $newCount,
        public int $totalCount,
        public string $panelUrl,
        public bool $isFirstRun,
        public string $siteName,
        ?string $locale = null,
    ) {
        $this->locale($locale ?? (string) (config('security-scanner.mail.locale') ?? config('app.locale', 'en')));
    }

    public function envelope(): Envelope
    {
        // The first pass is an inventory, not an event of the day. The subject must say so,
        // otherwise the first mail after installing the package reads as "we
        // were hacked today".
        $subject = $this->isFirstRun
            ? __('security-scanner::ui.Security baseline inventory: :count findings', ['count' => $this->newCount])
            : __('security-scanner::ui.Security findings: :count new', ['count' => $this->newCount]);

        return new Envelope(subject: sprintf('[%s] %s', $this->siteName, $subject));
    }

    public const string DEFAULT_VIEW = 'security-scanner::mail.findings';

    /**
     * The stock view is MARKDOWN (`<x-mail::message>`), and renders only as
     * `markdown:`: a plain `view:` does not register the `mail::` namespace, and the mail failed with
     * "No hint path defined for [mail]" on every host without its own view.
     * A view overridden by the host (`mail.view`) is plain Blade/HTML, as before.
     */
    public function content(): Content
    {
        /** @var view-string $view */
        $view = (string) config('security-scanner.mail.view', self::DEFAULT_VIEW);

        return $view === self::DEFAULT_VIEW
            ? new Content(markdown: $view)
            : new Content(view: $view);
    }
}
