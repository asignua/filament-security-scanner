<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Tests\Concerns\MakesFindings;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Database\Migrations\Migration;

class LegacyTitleMigrationTest extends TestCase
{
    use MakesFindings;

    private function migration(): Migration
    {
        return require __DIR__.'/../../database/migrations/2026_09_22_000002_rename_legacy_ee_titles_in_security_findings.php';
    }

    public function test_legacy_ee_titles_are_rewritten_and_the_rest_untouched(): void
    {
        $legacy = $this->makeFinding('a/one.php', ['title' => 'ee.PHP code inside a binary file']);
        $current = $this->makeFinding('a/two.php');

        $this->migration()->up();
        $this->migration()->up(); // idempotent

        $this->assertSame('security-scanner::rules.PHP code inside a binary file', $legacy->fresh()?->title);
        $this->assertSame('security-scanner::rules.Executable file in an upload directory', $current->fresh()?->title);
    }

    public function test_it_is_a_no_op_without_rows(): void
    {
        $this->migration()->up();

        $this->assertSame(0, SecurityFinding::query()->count());
    }
}
