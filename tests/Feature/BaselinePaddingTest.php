<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Models\SecurityBaselineEntry;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

/**
 * PostgreSQL pads `char(64)` with spaces: a 32-char xxh128 comes back with 32 trailing blanks.
 * SQLite does not, so the padding is simulated by writing it into the row.
 */
class BaselinePaddingTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-pad-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($this->root.'/vendor/acme');
        file_put_contents($this->root.'/vendor/acme/a.txt', 'one');
        $this->app->setBasePath($this->root);
        config(['security-scanner.zones' => ['vendor' => ['root' => 'vendor', 'kind' => 'vendor']]]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    public function test_a_blank_padded_stored_hash_is_not_reported_as_modified(): void
    {
        Artisan::call('security:baseline', ['--zone' => ['vendor']]);

        foreach (SecurityBaselineEntry::query()->get() as $entry) {
            SecurityBaselineEntry::query()->whereKey($entry->getKey())
                ->update(['content_hash' => str_pad($entry->content_hash, 64)]);
        }

        Artisan::call('security:scan', ['--trigger' => 'deploy', '--fail-on' => 'none']);

        $this->assertSame([], SecurityFinding::query()->where('rule_id', 'code.baseline-modified')->pluck('path')->all());
    }
}
