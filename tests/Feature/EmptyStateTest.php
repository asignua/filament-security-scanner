<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecurityScanStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityScanTrigger;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages\ListSecurityFindings;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Livewire\Livewire;

class EmptyStateTest extends TestCase
{
    public function test_the_empty_list_tells_the_admin_to_run_the_scan_in_every_locale(): void
    {
        Gate::define('security-scanner.view', static fn (): bool => true);

        foreach (['de', 'en', 'es', 'fr', 'it', 'nl', 'pl', 'pt_BR', 'tr', 'uk'] as $locale) {
            app()->setLocale($locale);

            Livewire::test(ListSecurityFindings::class)
                ->assertSee('security:scan')
                ->assertDontSee('security-scanner::ui.');
        }
    }

    public function test_after_a_scan_the_empty_state_says_scans_ran_and_found_nothing(): void
    {
        Gate::define('security-scanner.view', static fn (): bool => true);

        $scan = new SecurityScan;
        $scan->ulid = (string) Str::ulid();
        $scan->trigger = SecurityScanTrigger::Schedule;
        $scan->status = SecurityScanStatus::Ok;
        $scan->started_at = now();
        $scan->finished_at = now();
        $scan->save();

        foreach (['de', 'en', 'es', 'fr', 'it', 'nl', 'pl', 'pt_BR', 'tr', 'uk'] as $locale) {
            app()->setLocale($locale);

            Livewire::test(ListSecurityFindings::class)
                ->assertSee(__('security-scanner::ui.Scans have run, nothing found'))
                ->assertDontSee(__('security-scanner::ui.Nothing is listed until a scan has run. Run php artisan security:scan to start the first one.'))
                ->assertDontSee('security-scanner::ui.');
        }
    }
}
