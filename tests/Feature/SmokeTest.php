<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\SecurityScannerPlugin;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Filament\Facades\Filament;

class SmokeTest extends TestCase
{
    public function test_the_panel_boots(): void
    {
        $this->assertSame('admin', Filament::getCurrentPanel()?->getId());
    }

    public function test_the_plugin_is_registered_on_the_panel(): void
    {
        $panel = Filament::getPanel('admin');

        $this->assertTrue($panel->hasPlugin('asignua-filament-security-scanner'));
        $this->assertInstanceOf(SecurityScannerPlugin::class, $panel->getPlugin('asignua-filament-security-scanner'));
    }

    public function test_the_translations_are_loaded(): void
    {
        $this->assertSame('Sample', __('filament-security-scanner::filament-security-scanner.sample'));
    }
}
