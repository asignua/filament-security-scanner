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

        $this->assertTrue($panel->hasPlugin('security-scanner'));
        $this->assertInstanceOf(SecurityScannerPlugin::class, $panel->getPlugin('security-scanner'));
    }

    public function test_the_translations_are_loaded(): void
    {
        $this->assertSame('Security findings', __('security-scanner::ui.Security findings'));
    }
}
