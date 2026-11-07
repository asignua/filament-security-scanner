<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Asignua\FilamentSecurityScanner\Filament\Resources\Security\SecurityResource;
use Closure;
use Filament\Contracts\Plugin;
use Filament\Panel;

/**
 * Registers the findings resource on the host's panel.
 *
 *   $panel->plugin(SecurityScannerPlugin::make()->navigationGroup(fn () => __('System')));
 *
 * Pass the group as a CLOSURE rather than a string if it is translatable: the
 * panel registers at boot, while the locale is still app.locale.
 */
final class SecurityScannerPlugin implements Plugin
{
    private static string|Closure|null $navigationGroup = null;

    private static int $navigationSort = 10;

    public static function make(): static
    {
        return new self;
    }

    public function getId(): string
    {
        return 'security-scanner';
    }

    public function navigationGroup(string|Closure|null $group): static
    {
        self::$navigationGroup = $group;

        return $this;
    }

    public function navigationSort(int $sort): static
    {
        self::$navigationSort = $sort;

        return $this;
    }

    public static function resolvedNavigationGroup(): ?string
    {
        $group = self::$navigationGroup;

        return $group instanceof Closure ? (string) $group() : $group;
    }

    public static function resolvedNavigationSort(): int
    {
        return self::$navigationSort;
    }

    public function register(Panel $panel): void
    {
        $panel->resources([SecurityResource::class]);
    }

    public function boot(Panel $panel): void {}
}
