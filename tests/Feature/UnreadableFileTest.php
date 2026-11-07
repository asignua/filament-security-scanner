<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Models\SecurityScan;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

/**
 * Entries whose metadata the web user cannot read (a `0444` directory lists but
 * does not stat; a `0000` file does not open) must not crash a scanner, and must
 * not close findings.
 */
class UnreadableFileTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-unreadfile-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/storage/app/public/uploads/ro');
        File::ensureDirectoryExists($this->root.'/public/ro');
        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');

        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.zones' => [
                'storage_public' => ['root' => 'storage/app/public', 'kind' => 'upload:web'],
                'public' => ['root' => 'public', 'kind' => 'webroot'],
            ],
        ]);

        file_put_contents($this->root.'/storage/app/public/uploads/ro/a.txt', 'x');
        file_put_contents($this->root.'/public/ro/a.txt', 'x');
    }

    protected function tearDown(): void
    {
        @chmod($this->root.'/storage/app/public/uploads/ro', 0755);
        @chmod($this->root.'/public/ro', 0755);
        @chmod($this->root.'/storage/app/public/uploads/pic.jpg', 0644);
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    private function asWebUser(callable $callback): void
    {
        $dropped = function_exists('posix_geteuid') && posix_geteuid() === 0;

        if ($dropped && !posix_seteuid(65534)) {
            $this->markTestSkipped('Cannot drop privileges to emulate the web user.');
        }

        try {
            $callback();
        } finally {
            if ($dropped) {
                posix_seteuid(0);
            }
        }
    }

    public function test_a_directory_that_lists_but_does_not_stat_does_not_crash_any_scanner(): void
    {
        chmod($this->root.'/storage/app/public/uploads/ro', 0444);
        chmod($this->root.'/public/ro', 0444);

        $this->asWebUser(function (): void {
            Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
        });

        $scan = SecurityScan::query()->latest('id')->firstOrFail();
        $issues = implode("\n", $scan->scanners['issues'] ?? []);

        $this->assertStringNotContainsString('crashed', $issues);
        $this->assertContains('uploads', $scan->scanners['incomplete'] ?? []);
        $this->assertContains('obfuscation', $scan->scanners['incomplete'] ?? []);
        $this->assertContains('hygiene', $scan->scanners['incomplete'] ?? []);
        $this->assertTrue(SecurityFinding::query()->where('rule_id', 'hygiene.scanner-degraded')->exists());
    }

    public function test_an_unreadable_file_keeps_its_content_finding_open(): void
    {
        $path = $this->root.'/storage/app/public/uploads/pic.jpg';
        file_put_contents($path, 'GIF89a<?php echo "neutralized"; ?>');

        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
        $finding = SecurityFinding::query()->where('rule_id', 'obf.php-after-binary')->firstOrFail();
        $this->assertSame(SecurityFindingStatus::New, $finding->status);

        chmod($path, 0000);
        touch($path, time() + 5);

        $this->asWebUser(function (): void {
            Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);
        });

        $this->assertSame(SecurityFindingStatus::New, $finding->fresh()?->status, 'chmod 000 must not close the finding.');
        $scan = SecurityScan::query()->latest('id')->firstOrFail();
        $this->assertContains('obfuscation', $scan->scanners['incomplete'] ?? []);
    }
}
