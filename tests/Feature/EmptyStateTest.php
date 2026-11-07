<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages\ListSecurityFindings;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Gate;
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
}
