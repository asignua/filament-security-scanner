<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Asignua\FilamentSecurityScanner\Console\SecurityBaselineCommand;
use Asignua\FilamentSecurityScanner\Console\SecurityNotifyCommand;
use Asignua\FilamentSecurityScanner\Console\SecurityPruneCommand;
use Asignua\FilamentSecurityScanner\Console\SecurityRulesCommand;
use Asignua\FilamentSecurityScanner\Console\SecurityScanCommand;
use Asignua\FilamentSecurityScanner\Events\SecurityScanFinished;
use Asignua\FilamentSecurityScanner\Listeners\NotifyAboutSecurityFindings;
use Asignua\FilamentSecurityScanner\Scanning\MediaUploadScanObserver;
use Illuminate\Console\Scheduling\Schedule as LaravelSchedule;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Spatie\MediaLibrary\MediaCollections\Events\MediaHasBeenAddedEvent;

/**
 * The package service provider. boot() does NOT read the scanner config: host
 * providers boot AFTER package ones and layer their own values on top, so
 * everything that depends on config is read at call time.
 */
class SecurityScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-scanner.php', 'security-scanner');
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'security-scanner');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'security-scanner');

        $this->publishes([
            __DIR__.'/../config/security-scanner.php' => config_path('security-scanner.php'),
        ], 'security-scanner-config');

        // NO runningInConsole(): host buttons (an admin "tools" page, say) call these
        // commands through Artisan::call() from an HTTP request, not only from the console.
        $this->commands([
            SecurityScanCommand::class,
            SecurityBaselineCommand::class,
            SecurityRulesCommand::class,
            SecurityPruneCommand::class,
            SecurityNotifyCommand::class,
        ]);

        $this->callAfterResolving(LaravelSchedule::class, static function (LaravelSchedule $schedule): void {
            Schedule::register($schedule);
        });

        Event::listen(SecurityScanFinished::class, [NotifyAboutSecurityFindings::class, 'handle']);

        // Reacting to uploads only makes sense when the media library is installed
        // (it is a `suggest`). It hooks MediaHasBeenAddedEvent rather than Eloquent
        // `created`: the file is not on disk yet when `created` fires. The listener
        // checks the on/off switches itself on every call.
        if (class_exists(MediaHasBeenAddedEvent::class)) {
            Event::listen(MediaHasBeenAddedEvent::class, [MediaUploadScanObserver::class, 'handle']);
        }
    }
}
