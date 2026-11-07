<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

class StorageLinkTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-link-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/storage/app/public');
        File::ensureDirectoryExists($this->root.'/public');
        file_put_contents($this->root.'/.env', 'APP_KEY=inert');
        $this->app->setBasePath($this->root);
        $this->app->useStoragePath($this->root.'/storage');

        config([
            'filesystems.disks.public.root' => $this->root.'/storage/app/public',
            'security-scanner.zones' => [
                'public' => ['root' => 'public', 'kind' => 'webroot'],
            ],
        ]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    public function test_the_real_storage_link_stays_allowlisted(): void
    {
        symlink($this->root.'/storage/app/public', $this->root.'/public/storage');

        $this->assertFalse(ScanContext::isForeignStorageLink($this->root.'/public/storage'));

        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);

        $this->assertSame([], SecurityFinding::query()->where('rule_id', 'hygiene.foreign-storage-link')->pluck('path')->all());
    }

    public function test_a_storage_link_to_the_project_root_is_not_trusted_and_is_reported(): void
    {
        symlink($this->root, $this->root.'/public/storage');

        $this->assertTrue(ScanContext::isForeignStorageLink($this->root.'/public/storage'));

        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);

        $this->assertSame(['public/storage'], SecurityFinding::query()->where('rule_id', 'hygiene.foreign-storage-link')->pluck('path')->all());
    }
}
