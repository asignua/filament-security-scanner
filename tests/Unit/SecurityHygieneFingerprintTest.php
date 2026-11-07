<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\RuleSet;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Scanning\Scanners\EnvironmentHygieneScanner;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

/**
 * Each separate hygiene problem is a separate finding.
 *
 * The runner deduplicates by fingerprint (rule|scanner|path), while hygiene gave
 * the same "path" to different problems: all rejected heuristics, `proc_open`
 * and `allow_url_include` are all `php.ini`. The second and later
 * problems silently vanished: only the first reached the panel and the alerts.
 */
final class SecurityHygieneFingerprintTest extends PureTestCase
{
    public function test_every_rejected_heuristic_is_its_own_finding(): void
    {
        $context = new ScanContext(
            base: '/app',
            zones: [],
            rules: new RuleSet([], [
                'heuristics.php: rule "a" without matcher',
                'heuristics.php: rule "b" with an invalid regex',
                'host: duplicate id "c" within one file',
            ]),
        );

        $fingerprints = [];

        foreach ((new EnvironmentHygieneScanner)->scan($context) as $finding) {
            /** @var Finding $finding */
            if ($finding->ruleId === 'hygiene.registry-rule-invalid') {
                $fingerprints[] = $finding->fingerprint();
            }
        }

        $this->assertCount(3, $fingerprints);
        $this->assertCount(3, array_unique($fingerprints), 'each rejected heuristic must have its own fingerprint');
    }
}
