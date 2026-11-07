<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;

/**
 * Immutable rule set after the merge.
 *
 * Together with the rules it carries `issues`: the list of entries rejected by the validator.
 * They are NOT dropped silently: the scanner turns each into a
 * `hygiene.registry-rule-invalid` finding, otherwise a corrupted rules file would look
 * like "fewer rules now, all is well".
 */
final readonly class RuleSet
{
    /**
     * @param array<string, Rule> $rules  by id
     * @param list<string>        $issues
     */
    public function __construct(
        public array $rules = [],
        public array $issues = [],
        public string $version = 'unknown',
    ) {}

    /**
     * @return list<Rule>
     */
    public function all(): array
    {
        return array_values($this->rules);
    }

    public function get(string $id): ?Rule
    {
        return $this->rules[$id] ?? null;
    }

    public function count(): int
    {
        return count($this->rules);
    }

    /**
     * @return list<Rule>
     */
    public function enabled(): array
    {
        return array_values(array_filter($this->all(), static fn (Rule $r): bool => $r->enabled));
    }

    /**
     * @return list<Rule>
     */
    public function forScanner(string $scanner): array
    {
        return array_values(array_filter(
            $this->enabled(),
            static fn (Rule $r): bool => $r->scanner === $scanner,
        ));
    }

    /**
     * @return list<Rule>
     */
    public function forZone(SecurityZoneKind $kind): array
    {
        return array_values(array_filter(
            $this->enabled(),
            static fn (Rule $r): bool => $r->appliesToZone($kind),
        ));
    }

    /**
     * Rules applicable to this particular file.
     *
     * `$scanner` is NOT a cosmetic filter but the boundary between scanners. Without it the zone
     * scanner would also execute the obfuscation rules; those need content, so EVERY
     * file of the zone would be read. Measured on a live tree: 69,565 media disk files took
     * 159 seconds versus 52 with the filter.
     *
     * @return list<Rule>
     */
    public function covering(MatchSubject $subject, ?string $scanner = null): array
    {
        return array_values(array_filter(
            $this->enabled(),
            static fn (Rule $r): bool => ($scanner === null || $r->scanner === $scanner)
                && $r->covers($subject)
                && !$r->isAllowlisted($subject->path),
        ));
    }

    /**
     * Whether at least one applicable rule requires content. This question decides
     * whether to read the file from disk or make do with `pathinfo`; on a media disk the difference is between
     * seconds and minutes.
     */
    public function needsContent(MatchSubject $subject, ?string $scanner = null): bool
    {
        foreach ($this->covering($subject, $scanner) as $rule) {
            if ($rule->matcher->needsContent()) {
                return true;
            }
        }

        return false;
    }

    /**
     * The largest `max_read_bytes` among the applicable rules.
     */
    public function readBudget(MatchSubject $subject, ?string $scanner = null): int
    {
        $budget = 0;

        foreach ($this->covering($subject, $scanner) as $rule) {
            if ($rule->matcher->needsContent()) {
                $budget = max($budget, $rule->maxReadBytes);
            }
        }

        return $budget;
    }
}
