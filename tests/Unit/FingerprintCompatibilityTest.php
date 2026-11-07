<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

/**
 * Pins the fingerprint algorithm to values computed by the code of the
 * predecessor package (Finding::fingerprintFor under its old
 * namespace). The fingerprint is the dedupe key of stored
 * findings: if these values ever change, every closed finding in an upgraded
 * database resurfaces as new and quarantined files lose their link.
 */
final class FingerprintCompatibilityTest extends PureTestCase
{
    public function test_fingerprint_with_content_hash_matches_the_predecessor(): void
    {
        $this->assertSame(
            'a71b58eee2ddf0581b72b49d0ebce4c4bae82c8fb028f7a484c37bca1f1f19fd',
            Finding::fingerprintFor('obf.php-after-binary', 'obfuscation', 'storage/app/public/photos/a.jpg', 'abc123'),
        );
    }

    public function test_fingerprint_without_content_hash_matches_the_predecessor(): void
    {
        $this->assertSame(
            '453d23c91ed0aa65162910b275638896ad83e9c245761691013fbf9faa2f59e6',
            Finding::fingerprintFor('upload.executable-file', 'upload', 'storage/app/public/x.php', null),
        );
    }

    public function test_hygiene_fingerprint_for_a_synthetic_path_matches_the_predecessor(): void
    {
        $this->assertSame(
            '8a21d000820aae710ed7dddc8ff4907b53b0787bb418a1bdedc4fa00dd3dc30e',
            Finding::fingerprintFor('hygiene.registry-rule-invalid', 'hygiene', 'heuristics#0123456789ab', null),
        );
    }
}
