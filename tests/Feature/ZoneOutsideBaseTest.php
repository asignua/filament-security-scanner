<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Scanning\Zones;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Support\Facades\File;

class ZoneOutsideBaseTest extends TestCase
{
    public function test_a_zone_outside_the_project_root_is_refused_with_an_issue(): void
    {
        $base = sys_get_temp_dir().'/ss-zbase-'.bin2hex(random_bytes(4));
        $outside = sys_get_temp_dir().'/ss-zout-'.bin2hex(random_bytes(4));
        File::ensureDirectoryExists($base.'/public');
        File::ensureDirectoryExists($outside);
        config([
            'filesystems.disks.out.driver' => 'local',
            'filesystems.disks.out.root' => $outside,
            'security-scanner.zones' => [
                'public' => ['root' => 'public', 'kind' => 'webroot'],
                'out' => ['disk' => 'out', 'kind' => 'upload:web'],
                'dots' => ['root' => '../elsewhere', 'kind' => 'upload:web'],
            ],
        ]);

        [$zones, $issues] = Zones::resolve($base);

        $this->assertSame(['public'], array_map(static fn ($z) => $z->name, $zones));
        $this->assertCount(2, $issues);
        $this->assertStringContainsString('outside the project root', implode("\n", $issues));

        File::deleteDirectory($base);
        File::deleteDirectory($outside);
    }
}
