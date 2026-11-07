<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Scanning\Exceptions\InvalidSecurityRuleException;
use Asignua\FilamentSecurityScanner\Scanning\Rule;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

/**
 * Validation of a registry entry.
 *
 * The most important test here is the one that forbids `deterministic` on a regex. It
 * is the structural guarantee of auto-quarantine: if it breaks, a heuristic gains the right
 * to silently move other people's files, and no other safeguard will catch it.
 */
final class SecurityRuleValidationTest extends PureTestCase
{
    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function valid(array $overrides = []): array
    {
        return array_merge([
            'id' => 'obf.sample',
            'scanner' => 'obfuscation',
            'severity' => 'high',
            'applies_to' => ['code'],
            'matcher' => ['type' => 'regex', 'pattern' => '~eval~'],
        ], $overrides);
    }

    public function test_a_valid_rule_is_built(): void
    {
        $rule = Rule::fromArray($this->valid(), 'package');

        $this->assertSame('obf.sample', $rule->id);
        $this->assertSame(SecuritySeverity::High, $rule->severity);
        $this->assertTrue($rule->enabled);
        $this->assertFalse($rule->deterministic);
    }

    /**
     * A regex MUST NOT enable auto-quarantine. The check is here, not in the quarantine
     * service, on purpose: the ban must act when the registry loads, so that
     * such a rule never survives to the file-system walk.
     */
    public function test_a_regex_rule_may_not_be_deterministic(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);
        $this->expectExceptionMessageMatches('~deterministic~');

        Rule::fromArray($this->valid(['deterministic' => true]), 'package');
    }

    public function test_an_extension_rule_may_be_deterministic(): void
    {
        $rule = Rule::fromArray($this->valid([
            'id' => 'uploads.exe',
            'scanner' => 'uploads',
            'deterministic' => true,
            'applies_to' => ['upload:web'],
            'matcher' => ['type' => 'extension', 'extensions' => ['php']],
        ]), 'package');

        $this->assertTrue($rule->deterministic);
    }

    /**
     * A typo in a key name is the quietest way to spoil an import: a misspelled `applies_to`
     * would simply vanish, and the rule would apply nowhere or,
     * conversely, everywhere.
     */
    public function test_an_unknown_key_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);
        $this->expectExceptionMessageMatches('~unknown keys~');

        Rule::fromArray($this->valid(['aplies_to' => ['code']]), 'package');
    }

    public function test_an_uncompilable_pattern_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);
        $this->expectExceptionMessageMatches('~does not compile~');

        Rule::fromArray($this->valid(['matcher' => ['type' => 'regex', 'pattern' => '~([unclosed~']]), 'package');
    }

    public function test_an_unknown_severity_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);

        Rule::fromArray($this->valid(['severity' => 'apocalyptic']), 'package');
    }

    public function test_an_unknown_zone_kind_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);
        $this->expectExceptionMessageMatches('~zone kind~');

        Rule::fromArray($this->valid(['applies_to' => ['everywhere']]), 'package');
    }

    public function test_an_empty_applies_to_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);

        Rule::fromArray($this->valid(['applies_to' => []]), 'package');
    }

    public function test_an_unknown_scanner_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);

        Rule::fromArray($this->valid(['scanner' => 'antivirus']), 'package');
    }

    public function test_a_malformed_id_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);

        Rule::fromArray($this->valid(['id' => 'NoPrefix']), 'package');
    }

    public function test_an_unknown_matcher_type_is_rejected(): void
    {
        $this->expectException(InvalidSecurityRuleException::class);
        $this->expectExceptionMessageMatches('~unknown matcher.type~');

        Rule::fromArray($this->valid(['matcher' => ['type' => 'yara', 'pattern' => 'x']]), 'package');
    }
}
