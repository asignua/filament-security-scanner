<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\SecurityScanner;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

/**
 * The two negative tests are the most valuable here. Empty zones and mixed-up
 * exclusion lists give the SAME symptom: the scanner runs, reports "clean" and
 * looks nowhere. That is the worst failure mode of a detection subsystem, and the
 * config is the only place it can be caught.
 */
class ConfigValidationTest extends PureTestCase
{
    /**
     * @return list<string>
     */
    private function problemsFor(string $needle): array
    {
        return array_values(array_filter(
            SecurityScanner::validateConfig(),
            static fn (string $p): bool => str_contains($p, $needle),
        ));
    }

    /**
     * The key may be missing from the RESOLVED config if a deploy cached it before
     * the package appeared. A strict check here would break exactly the deploy that
     * brings this feature in.
     */
    public function test_a_missing_security_section_is_not_an_error(): void
    {
        config(['security-scanner' => null]);

        $this->assertSame([], $this->problemsFor('security-scanner.'));
    }

    public function test_empty_zones_are_reported(): void
    {
        config(['security-scanner.zones' => []]);

        $this->assertNotEmpty($this->problemsFor('security-scanner.zones'));
    }

    public function test_a_zone_with_an_unknown_kind_is_reported(): void
    {
        config(['security-scanner.zones' => ['x' => ['root' => 'public', 'kind' => 'everywhere']]]);

        $this->assertNotEmpty($this->problemsFor('security-scanner.zones'));
    }

    /**
     * Exactly one of `root`/`disk`. Both together are ambiguous, neither means
     * a zone without a root, which the scanner would silently skip.
     */
    public function test_a_zone_must_carry_exactly_one_root_or_disk(): void
    {
        config(['security-scanner.zones' => ['x' => ['kind' => 'webroot']]]);
        $this->assertNotEmpty($this->problemsFor('security-scanner.zones'));

        config(['security-scanner.zones' => ['x' => ['kind' => 'webroot', 'root' => 'public', 'disk' => 'media']]]);
        $this->assertNotEmpty($this->problemsFor('security-scanner.zones'));
    }

    public function test_a_valid_zone_set_passes(): void
    {
        config(['security-scanner.zones' => [
            'webroot' => ['root' => 'public', 'kind' => 'webroot'],
            'media' => ['disk' => 'media', 'kind' => 'upload:private'],
        ]]);

        $this->assertSame([], $this->problemsFor('security-scanner.zones'));
    }

    public function test_a_missing_allowlist_list_is_reported(): void
    {
        config(['security-scanner.allowlist' => ['scan' => ['a/**']]]);

        $this->assertNotEmpty($this->problemsFor('security-scanner.allowlist'));
    }

    public function test_a_valid_allowlist_passes(): void
    {
        config(['security-scanner.allowlist' => ['scan' => ['a/**'], 'baseline' => ['b/**']]]);

        $this->assertSame([], $this->problemsFor('security-scanner.allowlist'));
    }
}
