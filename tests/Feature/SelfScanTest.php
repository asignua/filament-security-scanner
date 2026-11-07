<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

/**
 * The scanner must not report its own files. Its rules are full of the very
 * patterns it hunts (eval, base64_decode, __halt_compiler), so a careless rule or
 * zone would flag the plugin as soon as it lands in vendor/.
 */
class SelfScanTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root = sys_get_temp_dir().'/ss-self-'.bin2hex(random_bytes(4));
        $plugin = $this->root.'/vendor/asignua/filament-security-scanner';
        File::ensureDirectoryExists($plugin);

        // What a dist install contains (tests/ and workbench/ are export-ignored).
        foreach (['src', 'config', 'database', 'resources'] as $dir) {
            File::copyDirectory(__DIR__.'/../../'.$dir, $plugin.'/'.$dir);
        }

        // A copy of the same sources outside vendor, so the obfuscation scanner sees them too.
        File::copyDirectory(__DIR__.'/../../src', $this->root.'/app');
        File::copyDirectory(__DIR__.'/../../resources/heuristics', $this->root.'/app/heuristics');

        $this->app->setBasePath($this->root);
        config(['security-scanner.zones' => [
            'vendor' => ['root' => 'vendor', 'kind' => 'vendor'],
            'app' => ['root' => 'app', 'kind' => 'code'],
        ]]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->root);

        parent::tearDown();
    }

    public function test_the_plugin_installed_in_vendor_raises_no_finding(): void
    {
        Artisan::call('security:baseline', ['--zone' => ['vendor']]);
        Artisan::call('security:scan', ['--trigger' => 'deploy', '--fail-on' => 'none']);

        $paths = SecurityFinding::query()
            ->where('path', 'like', 'vendor/%')
            ->orWhere('path', 'like', 'app/%')
            ->pluck('rule_id', 'path')
            ->all();

        $this->assertSame([], $paths);
    }

    public function test_a_planted_file_next_to_the_plugin_is_still_caught(): void
    {
        Artisan::call('security:baseline', ['--zone' => ['vendor']]);
        file_put_contents($this->root.'/vendor/asignua/filament-security-scanner/src/planted.php', '<?php echo "neutralized";');
        Artisan::call('security:scan', ['--trigger' => 'deploy', '--fail-on' => 'none']);

        $this->assertTrue(SecurityFinding::query()->where('path', 'like', '%planted.php')->exists());
    }
}
