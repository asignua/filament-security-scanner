<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\Scanning\Rule;
use Asignua\FilamentSecurityScanner\Scanning\RuleRegistry;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;

/**
 * Merge of the two registry files (package -> host).
 *
 * The whole design rests on one thing: the host never edits the package's
 * `heuristics.php`; it layers its own file on top. The tests below pin down the
 * properties without which that promise is worthless.
 */
final class SecurityRuleRegistryMergeTest extends PureTestCase
{
    /** @var list<string> */
    private array $temp = [];

    protected function tearDown(): void
    {
        foreach ($this->temp as $file) {
            @unlink($file);
        }

        $this->temp = [];
        RuleRegistry::flush();

        parent::tearDown();
    }

    /**
     * @param list<array<string, mixed>> $rules
     * @param array<string, mixed>       $envelope
     */
    private function file(array $rules, array $envelope = []): string
    {
        $path = tempnam(sys_get_temp_dir(), 'heur').'.php';
        $payload = array_merge(['format' => 1, 'version' => 'test', 'rules' => $rules], $envelope);

        file_put_contents($path, '<?php return '.var_export($payload, true).';');
        $this->temp[] = $path;

        return $path;
    }

    /**
     * @return array<string, mixed>
     */
    private function rule(string $id, array $overrides = []): array
    {
        return array_merge([
            'id' => $id,
            'scanner' => 'obfuscation',
            'severity' => 'medium',
            'applies_to' => ['code'],
            'matcher' => ['type' => 'regex', 'pattern' => '~eval~'],
        ], $overrides);
    }

    public function test_a_later_file_overrides_an_earlier_one_by_id(): void
    {
        $set = RuleRegistry::load(files: [
            'package' => $this->file([$this->rule('obf.shared', ['severity' => 'low'])]),
            'host' => $this->file([$this->rule('obf.shared', ['severity' => 'critical'])]),
        ]);

        $this->assertSame('critical', $set->get('obf.shared')?->severity->value);
    }

    public function test_the_host_file_wins_over_the_package(): void
    {
        $set = RuleRegistry::load(files: [
            'package' => $this->file([$this->rule('obf.shared', ['severity' => 'critical'])]),
            'host' => $this->file([$this->rule('obf.shared', ['severity' => 'info'])]),
        ]);

        $this->assertSame('info', $set->get('obf.shared')?->severity->value);
    }

    /**
     * Disabling is `enabled => false` in the HOST file, never the removal of a
     * package entry. Otherwise the next package update would resurrect a rule that
     * was deliberately silenced, and would do it quietly.
     */
    public function test_the_host_file_can_disable_a_package_rule(): void
    {
        $set = RuleRegistry::load(files: [
            'package' => $this->file([$this->rule('obf.noisy')]),
            'host' => $this->file([$this->rule('obf.noisy', ['enabled' => false])]),
        ]);

        $rule = $set->get('obf.noisy');

        $this->assertNotNull($rule);
        $this->assertFalse($rule->enabled);
        $this->assertSame([], array_filter($set->enabled(), static fn (Rule $r): bool => $r->id === 'obf.noisy'));
    }

    /**
     * `source` is stamped by the LOADER from the originating file. If it were taken
     * from the entry, a host rule would declare itself `package`, and a rule from a
     * host file could pose as the package's own.
     */
    public function test_a_rule_cannot_forge_its_own_source(): void
    {
        $set = RuleRegistry::load(files: [
            'host' => $this->file([$this->rule('obf.liar', ['source' => 'package'])]),
        ]);

        $this->assertSame('host', $set->get('obf.liar')?->source);
    }

    public function test_an_invalid_rule_is_dropped_without_taking_the_file_down(): void
    {
        $set = RuleRegistry::load(files: [
            'package' => $this->file([
                $this->rule('obf.good'),
                $this->rule('obf.bad', ['severity' => 'nonsense']),
                $this->rule('obf.alsogood'),
            ]),
        ]);

        $this->assertNotNull($set->get('obf.good'));
        $this->assertNotNull($set->get('obf.alsogood'));
        $this->assertNull($set->get('obf.bad'));
        $this->assertCount(1, $set->issues);
    }

    public function test_a_duplicate_id_inside_one_file_is_reported(): void
    {
        $set = RuleRegistry::load(files: [
            'package' => $this->file([$this->rule('obf.twice'), $this->rule('obf.twice')]),
        ]);

        $this->assertCount(1, $set->issues);
        $this->assertStringContainsString('duplicate id', $set->issues[0]);
    }

    /**
     * A file of a newer schema is skipped ENTIRELY, not read partially: half of
     * an unintelligible format is worse than its absence, because it looks like a working set.
     */
    public function test_a_newer_schema_file_is_skipped_whole(): void
    {
        $set = RuleRegistry::load(files: [
            'package' => $this->file([$this->rule('obf.future')], ['format' => 99]),
        ]);

        $this->assertSame(0, $set->count());
        $this->assertStringContainsString('is newer than the supported', $set->issues[0]);
    }

    public function test_a_missing_file_is_simply_skipped(): void
    {
        $set = RuleRegistry::load(files: [
            'host' => '/no/such/heuristics.php',
            'package' => $this->file([$this->rule('obf.only')]),
        ]);

        $this->assertSame(1, $set->count());
        $this->assertSame([], $set->issues);
    }

    /**
     * An overridden set of files must not poison the memo for subsequent calls.
     */
    public function test_an_explicit_file_set_is_not_memoised(): void
    {
        RuleRegistry::load(files: ['package' => $this->file([$this->rule('obf.temp')])]);

        $this->assertNull(RuleRegistry::load(fresh: true)->get('obf.temp'));
    }
}
