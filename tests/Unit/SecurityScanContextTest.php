<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Scanning\RuleSet;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;
use Illuminate\Support\Carbon;

/**
 * The mtime gate for reading content, and its forced disabling.
 */
class SecurityScanContextTest extends PureTestCase
{
    public function test_an_old_file_is_not_read_again_by_default(): void
    {
        $context = $this->context(force: false);

        $this->assertFalse($context->shouldInspectContent('storage/app/certificates/old.pdf', $this->longAgo(), 'obfuscation'));
        $this->assertTrue($context->shouldInspectContent('storage/app/certificates/new.pdf', time(), 'obfuscation'));
    }

    /**
     * An added ZONE does not shift the gate: the scanner "already passed through it fully", so without
     * this flag the content of its old files would never be read.
     */
    public function test_reread_ignores_the_mtime_gate(): void
    {
        $context = $this->context(force: true);

        $this->assertTrue($context->shouldInspectContent('storage/app/certificates/old.pdf', $this->longAgo(), 'obfuscation'));
    }

    /**
     * mtime is set by the attacker (`touch -d`), ctime is not: the kernel bumps it on
     * any inode change, and `touch` itself updates it. A shell with a backdated
     * mtime must be read.
     */
    public function test_a_backdated_mtime_with_a_fresh_ctime_is_read(): void
    {
        $context = $this->context(force: false);

        $this->assertTrue($context->shouldInspectContent('storage/app/media/12/avatar.jpg', $this->longAgo(), 'obfuscation', time()));
        $this->assertFalse($context->shouldInspectContent('storage/app/media/12/old.jpg', $this->longAgo(), 'obfuscation', $this->longAgo()));
    }

    private function context(bool $force): ScanContext
    {
        return new ScanContext(
            base: '/app',
            zones: [],
            rules: new RuleSet,
            previousRunsByScanner: ['obfuscation' => Carbon::createFromTimestamp(time() - 3600)],
            forceContentRead: $force,
        );
    }

    private function longAgo(): int
    {
        return time() - 86400;
    }
}
