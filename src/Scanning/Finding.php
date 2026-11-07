<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;

/**
 * A finding handed over by a scanner. This is NOT a model; {@see ScanRunner} puts it into the DB.
 *
 * The split is deliberate: a scanner remains a pure function from (FS, rules) to
 * findings and is tested without a DB, while all decisions about dedup, statuses and closing
 * live in one place.
 *
 * `deterministic` travels on the finding rather than being asked of the rule later: then
 * the auto-quarantine decision is a single `if`, and the codebase has EXACTLY ONE
 * place where the machine can move a file.
 */
final readonly class Finding
{
    /**
     * `$title` is a translation KEY (`security-scanner::rules.…`), not text: it is translated by
     * {@see \Asignua\FilamentSecurityScanner\SecurityPresenter::ruleLabel()} at render time.
     *
     * @param list<Evidence> $evidence
     */
    public function __construct(
        public string $ruleId,
        public string $scanner,
        public SecuritySeverity $severity,
        public string $title,
        public string $path,
        public array $evidence = [],
        public ?string $zone = null,
        public ?SecurityZoneKind $zoneKind = null,
        public ?string $disk = null,
        public bool $deterministic = false,
        public ?int $size = null,
        public ?int $mtime = null,
        public ?string $contentHash = null,
        public ?string $registrySource = null,
        public ?string $registryVersion = null,
    ) {}

    /**
     * Stable fingerprint of the finding.
     *
     * Whether it includes the content hash is decided by the rule's MATCHER, not by a separate config
     * field. The logic is direct: a rule that looked at content describes exactly that
     * content, so its change is a new event (a shell that rewrites itself). A rule
     * that looked only at the name or path describes a location, and a regenerated
     * thumbnail at the same path must not wake anyone a second time.
     */
    public static function fingerprintFor(string $ruleId, string $scanner, string $path, ?string $contentHash): string
    {
        return hash('sha256', implode('|', array_filter([
            $ruleId,
            $scanner,
            PathNormalizer::relative($path),
            $contentHash,
        ], static fn (?string $v): bool => $v !== null && $v !== '')));
    }

    public function fingerprint(): string
    {
        return self::fingerprintFor($this->ruleId, $this->scanner, $this->path, $this->contentHash);
    }

    /**
     * Evidence in a form suitable for a json column.
     *
     * The excerpt is already escaped in {@see Evidence}, but `detail` is not: scanners
     * put file names, git paths and error texts there, i.e. bytes from the FS.
     * Broken UTF-8 there made `json_encode(JSON_THROW_ON_ERROR)` fail on save.
     *
     * @return list<array<string, mixed>>
     */
    public function evidenceArray(): array
    {
        return array_map(static fn (Evidence $e): array => [
            'ruleId' => $e->ruleId,
            'excerpt' => $e->excerpt,
            'offset' => $e->offset,
            'detail' => array_map(
                static fn (mixed $v): mixed => is_string($v) ? PathNormalizer::escapeBytes($v) : $v,
                $e->detail,
            ),
        ], $this->evidence);
    }
}
