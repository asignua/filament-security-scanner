<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages\ListSecurityFindings;
use Asignua\FilamentSecurityScanner\SecurityAlerts;
use Asignua\FilamentSecurityScanner\SecurityScanner;
use Asignua\FilamentSecurityScanner\Tests\Concerns\MakesFindings;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Filament\Notifications\Notification;
use Illuminate\Contracts\Translation\HasLocalePreference;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;
use Workbench\App\Models\User;

/**
 * Filament renders a notification body as (sanitized) HTML, and file names are
 * written by whoever can upload: an anchor in a name must stay text.
 */
class NotificationEscapingTest extends TestCase
{
    use MakesFindings;

    private const string EVIL = '<a href="https://evil.test/login">click</a>.php';

    protected function tearDown(): void
    {
        SecurityScanner::flush();

        parent::tearDown();
    }

    public function test_the_panel_notification_body_escapes_the_file_name(): void
    {
        $user = User::query()->firstOrFail();
        SecurityScanner::notifyUsersUsing(static fn () => new Collection([$user]));
        $this->makeFinding('storage/app/public/uploads/'.self::EVIL);

        SecurityAlerts::dispatch();

        $body = (string) ($user->notifications()->firstOrFail()->data['body'] ?? '');
        $this->assertStringNotContainsString('<a href', $body);
        $this->assertStringContainsString('&lt;a href', $body);
    }

    public function test_a_failed_quarantine_notification_escapes_the_message(): void
    {
        Gate::define('security-scanner.view', static fn (): bool => true);
        Gate::define('security-scanner.quarantine', static fn (): bool => true);
        $finding = $this->makeFinding('storage/app/public/uploads/'.self::EVIL);

        $root = sys_get_temp_dir().'/ss-esc-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($root.'/storage/app/public/uploads');
        $this->app->setBasePath($root);
        config(['security-scanner.zones' => ['storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web']]]);

        try {
            // The file does not exist, so the exception message carries the path.
            Livewire::test(ListSecurityFindings::class)
                ->callTableAction('quarantine', $finding)
                ->assertNotified(
                    Notification::make()
                        ->title(__('security-scanner::ui.Quarantine failed'))
                        ->body(e('The file does not exist or is a symlink: storage/app/public/uploads/'.self::EVIL))
                        ->danger(),
                );
        } finally {
            File::deleteDirectory($root);
        }
    }

    public function test_the_database_notification_is_written_in_the_recipients_locale(): void
    {
        app()->setLocale('en');
        $user = LocaleUser::query()->firstOrFail();
        SecurityScanner::notifyUsersUsing(static fn () => new Collection([$user]));
        $this->makeFinding('storage/app/public/uploads/a.php');

        SecurityAlerts::dispatch();

        $data = $user->notifications()->firstOrFail()->data;
        app()->setLocale('uk');
        $expected = __('security-scanner::ui.Security findings: :count new', ['count' => 1]);

        $this->assertSame($expected, $data['title'] ?? null);
        $this->assertNotSame('Security findings: 1 new', $data['title'] ?? null);
    }
}

class LocaleUser extends User implements HasLocalePreference
{
    protected $table = 'users';

    public function preferredLocale(): string
    {
        return 'uk';
    }
}
