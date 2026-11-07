<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SecurityScannerServiceProvider extends PackageServiceProvider
{
    public static string $name = 'filament-security-scanner';

    public function configurePackage(Package $package): void
    {
        // Translations live in resources/lang/<locale>/filament-security-scanner.php and are read as
        // `__('filament-security-scanner::filament-security-scanner.<key>')`. Publish tag: `filament-security-scanner-translations`.
        $package->name(static::$name)
            ->hasTranslations()
            ->hasViews();

        // Add a config file only when the plugin really has options: create config/filament-security-scanner.php and
        // chain `->hasConfigFile()` here (publish tag `filament-security-scanner-config`). Prefer fluent setters on the Plugin.
    }
}
