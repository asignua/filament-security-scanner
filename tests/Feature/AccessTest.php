<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Filament\Resources\Security\Pages\ListSecurityFindings;
use Asignua\FilamentSecurityScanner\Filament\Resources\Security\SecurityResource;
use Asignua\FilamentSecurityScanner\SecurityScanner;
use Asignua\FilamentSecurityScanner\Tests\Concerns\MakesFindings;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Filament\Facades\Filament;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;

/**
 * The package is DENY BY DEFAULT: a host that has not defined a gate gets no
 * access to findings or to quarantine for anybody. This is the first thing that
 * has to hold, everything else builds on it.
 */
class AccessTest extends TestCase
{
    use MakesFindings;

    private const array ABILITIES = ['view', 'quarantine', 'triage', 'restore'];

    private function allow(string ...$abilities): void
    {
        foreach ($abilities as $ability) {
            Gate::define('security-scanner.'.$ability, static fn (): bool => true);
        }
    }

    /**
     * @return list<string>
     */
    private function navigationUrls(): array
    {
        $urls = [];

        foreach (Filament::getNavigation() as $group) {
            foreach ($group->getItems() as $item) {
                if (str_contains($item->getUrl() ?? '', '/security')) {
                    $urls[] = (string) $item->getUrl();
                }
            }
        }

        return $urls;
    }

    public function test_with_no_gate_defined_every_ability_is_denied(): void
    {
        foreach (self::ABILITIES as $ability) {
            $this->assertFalse(SecurityScanner::can($ability), "[{$ability}] must be denied by default.");
        }
    }

    public function test_an_unknown_ability_is_denied(): void
    {
        $this->assertFalse(SecurityScanner::can('anything-else'));
    }

    public function test_a_guest_is_denied_even_when_the_gate_allows_everybody(): void
    {
        $this->allow(...self::ABILITIES);
        auth()->logout();

        foreach (self::ABILITIES as $ability) {
            $this->assertFalse(SecurityScanner::can($ability));
        }
    }

    public function test_the_resource_is_closed_and_hidden_without_the_view_gate(): void
    {
        $this->assertFalse(SecurityResource::canAccess());
        $this->assertNull(SecurityResource::getNavigationBadge());

        $this->get('/admin/security')->assertForbidden();
        $this->assertSame([], $this->navigationUrls());
    }

    public function test_the_view_gate_opens_the_resource(): void
    {
        $this->allow('view');

        $this->assertTrue(SecurityResource::canAccess());
        $this->assertCount(1, $this->navigationUrls());
        $this->get('/admin/security')->assertOk();
    }

    public function test_the_record_page_is_closed_without_the_view_gate(): void
    {
        $finding = $this->makeFinding();

        $this->get('/admin/security/'.$finding->getRouteKey())->assertForbidden();

        $this->allow('view');

        $this->get('/admin/security/'.$finding->getRouteKey())->assertOk();
    }

    public function test_triage_inherits_quarantine_when_it_has_no_definition(): void
    {
        $this->allow('quarantine');

        $this->assertTrue(SecurityScanner::can('triage'));
    }

    public function test_triage_does_not_inherit_view(): void
    {
        $this->allow('view');

        $this->assertFalse(SecurityScanner::can('triage'));
    }

    public function test_an_explicit_triage_gate_wins_over_the_inheritance(): void
    {
        $this->allow('quarantine');
        Gate::define('security-scanner.triage', static fn (): bool => false);

        $this->assertFalse(SecurityScanner::can('triage'));
    }

    public function test_restore_is_separate_from_quarantine(): void
    {
        $this->allow('view', 'quarantine', 'triage');

        $this->assertFalse(SecurityScanner::can('restore'));
    }

    public function test_row_actions_are_hidden_and_inert_without_their_gates(): void
    {
        $this->allow('view');
        $finding = $this->makeFinding();

        Livewire::test(ListSecurityFindings::class)
            ->assertTableActionHidden('acknowledge', $finding)
            ->assertTableActionHidden('ignore', $finding)
            ->assertTableActionHidden('quarantine', $finding)
            ->assertTableActionHidden('restore', $finding);

        // Calling a hidden action directly must not change anything either.
        foreach (['acknowledge', 'ignore', 'quarantine', 'restore'] as $action) {
            Livewire::test(ListSecurityFindings::class)
                ->call('mountTableAction', $action, (string) $finding->getKey())
                ->call('callMountedAction');
        }

        $this->assertSame(SecurityFindingStatus::New, $finding->fresh()?->status);
    }

    public function test_triage_actions_work_with_the_gate_and_sign_the_change(): void
    {
        $this->allow('view', 'triage');
        $finding = $this->makeFinding();

        Livewire::test(ListSecurityFindings::class)
            ->assertTableActionVisible('acknowledge', $finding)
            ->callTableAction('acknowledge', $finding)
            ->assertHasNoTableActionErrors();

        $fresh = $finding->fresh();

        $this->assertSame(SecurityFindingStatus::Acknowledged, $fresh?->status);
        $this->assertSame((int) auth()->id(), $fresh?->status_by_id);

        Livewire::test(ListSecurityFindings::class)->callTableAction('ignore', $finding);

        $this->assertSame(SecurityFindingStatus::Ignored, $finding->fresh()?->status);
    }
}
