<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Filament\Resources\Security\SecurityResource;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Filament\Facades\Filament;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;

class RegistrationTest extends TestCase
{
    public function test_the_plugin_registers_the_findings_resource(): void
    {
        $this->assertContains(SecurityResource::class, Filament::getPanel('admin')->getResources());
        $this->assertSame('security', SecurityResource::getSlug());
    }

    public function test_the_contract_tables_exist(): void
    {
        foreach (['security_scans', 'security_findings', 'security_baseline'] as $table) {
            $this->assertTrue(Schema::hasTable($table), "Table [{$table}] is part of the compatibility contract.");
        }
    }

    public function test_the_config_key_and_defaults_are_merged(): void
    {
        $this->assertTrue(config('security-scanner.enabled'));
        $this->assertSame('', config('security-scanner.tables.prefix'));
        $this->assertFalse(config('security-scanner.quarantine.auto'));
        $this->assertSame('security-scanner::mail.findings', config('security-scanner.mail.view'));
    }

    public function test_the_commands_are_registered_outside_the_console_check(): void
    {
        $commands = array_keys(Artisan::all());

        foreach (['security:scan', 'security:baseline', 'security:rules', 'security:prune', 'security:notify'] as $name) {
            $this->assertContains($name, $commands);
        }
    }

    public function test_the_package_schedules_its_own_commands(): void
    {
        $events = collect(app(Schedule::class)->events())->map(fn ($e): string => (string) $e->command);

        $this->assertTrue($events->contains(fn (string $c): bool => str_contains($c, 'security:scan')));
        $this->assertTrue($events->contains(fn (string $c): bool => str_contains($c, 'security:prune')));
        $this->assertTrue($events->contains(fn (string $c): bool => str_contains($c, 'security:notify')));
    }

    public function test_the_shipped_rules_pass_the_validation_gate(): void
    {
        $this->assertSame(0, Artisan::call('security:rules', ['--validate' => true]));
    }

    public function test_the_mail_view_and_translations_resolve(): void
    {
        $this->assertTrue(view()->exists('security-scanner::mail.findings'));
        $this->assertSame('Open', __('security-scanner::ui.Open'));
    }
}
