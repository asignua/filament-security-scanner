<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages\ViewSecurityFinding;
use Asignua\FilamentSecurityScanner\Tests\Concerns\MakesFindings;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;

class EvidenceDisplayTest extends TestCase
{
    use MakesFindings;

    public function test_the_evidence_section_shows_each_items_rule_and_excerpt(): void
    {
        Gate::define('security-scanner.view', static fn (): bool => true);
        $finding = $this->makeFinding(attributes: ['evidence' => [
            ['ruleId' => 'uploads.executable-extension', 'excerpt' => 'EXCERPT-ONE', 'offset' => 7, 'detail' => []],
            ['ruleId' => 'obfuscation.eval', 'excerpt' => 'EXCERPT-TWO', 'offset' => null, 'detail' => []],
        ]]);

        Livewire::test(ViewSecurityFinding::class, ['record' => $finding->getRouteKey()])
            ->assertSee('uploads.executable-extension @7: EXCERPT-ONE', false)
            ->assertSee('obfuscation.eval: EXCERPT-TWO', false);
    }

    public function test_the_hidden_evidence_label_is_translated(): void
    {
        Gate::define('security-scanner.view', static fn (): bool => true);
        $finding = $this->makeFinding(attributes: ['evidence' => [
            ['ruleId' => 'r', 'excerpt' => 'x', 'offset' => null, 'detail' => []],
        ]]);
        app()->setLocale('uk');

        $html = Livewire::test(ViewSecurityFinding::class, ['record' => $finding->getRouteKey()])->html();

        $this->assertNotSame('Evidence', __('security-scanner::ui.Evidence'));
        // The section heading AND the screen-reader label of the entry.
        $this->assertGreaterThanOrEqual(2, substr_count($html, __('security-scanner::ui.Evidence')));
    }
}
