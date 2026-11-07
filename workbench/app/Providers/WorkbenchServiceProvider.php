<?php

declare(strict_types=1);

namespace Workbench\App\Providers;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

/**
 * Demo-only: opens the four security-scanner gates to every workbench user so the
 * browser flow can be tried. Real applications define their own (see the README).
 * It is registered in testbench.yaml only, never in the test suite, so the
 * deny-by-default tests run without any gate.
 */
class WorkbenchServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        foreach (['view', 'quarantine', 'triage', 'restore'] as $ability) {
            Gate::define('security-scanner.'.$ability, static fn (): bool => true);
        }
    }
}
