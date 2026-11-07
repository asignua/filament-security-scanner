<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning\Scanners;

use Asignua\FilamentSecurityScanner\Scanning\Contracts\Scanner;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Asignua\FilamentSecurityScanner\Scanning\MatchSubject;
use Asignua\FilamentSecurityScanner\Scanning\PathNormalizer;
use Asignua\FilamentSecurityScanner\Scanning\ScanContext;
use Asignua\FilamentSecurityScanner\Scanning\UnreadableDirectories;
use Asignua\FilamentSecurityScanner\Scanning\Zone;
use Generator;
use SplFileInfo;
use Throwable;

/**
 * Structural zone scanner: what lies where it must not lie.
 *
 * This scanner is the one that would have caught the incident of 2026-09-20: three executable files in
 * storage/app/public that survived all deploys because the directory is under .gitignore. That is why it is
 * first of the four, not last.
 *
 * The cost is held by three decisions:
 *
 *  1. The walk takes ONLY metadata (`pathinfo`, `stat`). On the production media disk this is
 *     69,344 files; reading their content on every nightly pass is impossible.
 *  2. Content is read only when at least one APPLICABLE rule wants it
 *     ({@see \Asignua\FilamentSecurityScanner\Scanning\RuleSet::needsContent()}), and no more than
 *     the greediest of them asks for.
 *  3. A file larger than `security.max_file_size` is checked by extension
 *     but not read, and a separate info-level finding is created about that.
 *     Silence is not the same as clean.
 *
 * SYMLINKS ARE NOT FOLLOWED. Otherwise the scanner would check the target instead of the
 * fact of the link itself, and escaping the zone boundary is exactly what needs to be noticed.
 */
final class UploadZoneScanner implements Scanner
{
    /** @var list<string> */
    private array $issues = [];

    public function id(): string
    {
        return 'uploads';
    }

    public function enabled(): bool
    {
        return (bool) config('security-scanner.enabled', false);
    }

    /**
     * @return list<string>
     */
    public function issues(): array
    {
        return $this->issues;
    }

    /**
     * @return Generator<Finding>
     */
    public function scan(ScanContext $context): Generator
    {
        foreach ($context->zones as $zone) {
            // A zone for whose KIND this scanner has no rule at all is not even
            // walked. Without this an added `vendor` (16k files) would be iterated
            // every night only to get an
            // empty rule list on each file.
            if ($context->rules->forZone($zone->kind) === []
                || $this->rulesForKind($context, $zone) === []) {
                continue;
            }

            if ($context->outOfTime()) {
                $this->issues[] = sprintf('time budget exhausted before zone "%s"', $zone->name);

                return;
            }

            yield from $this->scanZone($zone, $context);
        }
    }

    /**
     * Rules of THIS scanner applicable to the zone kind.
     *
     * @return list<\Asignua\FilamentSecurityScanner\Scanning\Rule>
     */
    private function rulesForKind(ScanContext $context, Zone $zone): array
    {
        return array_values(array_filter(
            $context->rules->forZone($zone->kind),
            fn (\Asignua\FilamentSecurityScanner\Scanning\Rule $r): bool => $r->scanner === $this->id(),
        ));
    }

    /**
     * @return Generator<Finding>
     */
    private function scanZone(Zone $zone, ScanContext $context): Generator
    {
        foreach ($this->candidates($zone, $context) as $file) {
            if ($context->outOfTime()) {
                $this->issues[] = sprintf('time budget exhausted in zone "%s"', $zone->name);

                return;
            }

            $absolute = $file->getPathname();
            $relative = PathNormalizer::relative($absolute, $context->base);

            if ($context->isAllowlisted($relative) || !$context->covers($relative)) {
                continue;
            }

            $context->filesSeen?->add($relative);

            $isSymlink = $file->isLink();
            $size = 0;
            $mtime = null;

            if (!$isSymlink) {
                // getSize()/getMTime() THROW on a failed stat (`@` does not help): a
                // directory with mode 0444 lists its entries but does not stat them.
                try {
                    $size = (int) $file->getSize();
                    $mtime = (int) $file->getMTime();
                } catch (Throwable) {
                    $context->issues?->addUnreadableFile($this->id(), $relative, 'cannot be stat-ed');
                }
            }

            $subject = MatchSubject::make(
                path: $absolute,
                zoneKind: $zone->kind,
                base: $context->base,
                size: $size,
                bytes: null,
                isSymlink: $isSymlink,
            );

            // Only OWN rules. Otherwise this scanner would drag in the obfuscation
            // heuristics, which need content, and every file of the zone would be read.
            $rules = $context->rules->covering($subject, $this->id());

            if ($rules === []) {
                continue;
            }

            [$subject, $contentHash] = $this->withContentIfNeeded($subject, $context, $absolute, $size, $isSymlink);

            foreach ($rules as $rule) {
                // `covering()` above filtered only by PATH; allowlist.hashes
                // sees concrete content only here, when it has already been read
                // (`$contentHash` can be `null` for rules without content, in which case
                // a hash entry in the allowlist simply silences nothing, and that is correct).
                if ($rule->isAllowlisted($subject->path, $contentHash)) {
                    continue;
                }

                $evidence = $rule->evaluate($subject);

                if ($evidence === []) {
                    continue;
                }

                // A file with a suspicious extension is the first candidate for content
                // reading by the obfuscation scanner, however old its mtime is.
                $context->candidates?->add($relative, $this->id());

                yield new Finding(
                    ruleId: $rule->id,
                    scanner: $this->id(),
                    severity: $rule->severity,
                    title: $rule->message,
                    path: $relative,
                    evidence: $evidence,
                    zone: $zone->name,
                    zoneKind: $zone->kind,
                    disk: $zone->disk,
                    deterministic: $rule->deterministic,
                    size: $size,
                    mtime: $mtime,
                    // The hash is set only when the rule really looked at content;
                    // this is what decides whether it goes into the fingerprint.
                    contentHash: $rule->matcher->needsContent() ? $contentHash : null,
                    registrySource: $rule->source,
                    registryVersion: $rule->version,
                );
            }
        }
    }

    /**
     * @return array{0: MatchSubject, 1: string|null}
     */
    private function withContentIfNeeded(
        MatchSubject $subject,
        ScanContext $context,
        string $absolute,
        int $size,
        bool $isSymlink,
    ): array {
        if ($isSymlink || !$context->rules->needsContent($subject, $this->id())) {
            return [$subject, null];
        }

        // An oversized file is not read; the finding about it is issued by the obfuscation scanner,
        // which is responsible for reading content.
        if ($size > $context->maxFileSize) {
            return [$subject, null];
        }

        $budget = max(1, $context->rules->readBudget($subject, $this->id()));

        try {
            $handle = @fopen($absolute, 'rb');

            if ($handle === false) {
                $this->issues[] = sprintf('file cannot be opened: %s', $subject->path);

                return [$subject, null];
            }

            $bytes = (string) fread($handle, $budget);
            fclose($handle);
        } catch (Throwable $e) {
            $this->issues[] = sprintf('read error %s: %s', $subject->path, $e->getMessage());

            return [$subject, null];
        }

        return [
            new MatchSubject(
                path: $subject->path,
                basename: $subject->basename,
                extensionChain: $subject->extensionChain,
                zoneKind: $subject->zoneKind,
                size: $subject->size,
                bytes: $bytes,
                isSymlink: false,
            ),
            hash('sha256', $bytes),
        ];
    }

    /**
     * Source of zone candidates: a full walk, or, when the run is narrowed to
     * specific paths (reaction to an upload, A10), one
     * `file_exists()` per given path instead of walking the whole zone.
     * A targeted run must cost O(number of paths), not O(zone size):
     * without it a single suspicious upload would start a full walk of 69,565
     * media disk files, and the 60-second upload-reaction job would be killed
     * mid-walk without ever reaching the file itself.
     *
     * @return Generator<SplFileInfo>
     */
    private function candidates(Zone $zone, ScanContext $context): Generator
    {
        if ($context->restrictToPaths === []) {
            yield from $this->walk($zone, $context);

            return;
        }

        yield from $zone->restrictedCandidates($context->restrictToPaths, $context->base);
    }

    /**
     * @return Generator<SplFileInfo>
     */
    private function walk(Zone $zone, ScanContext $context): Generator
    {
        $unreadable = new UnreadableDirectories;

        try {
            // Walk flags and cutting out nested zones are in Zone::iterator():
            // the structural scanner, the hash snapshot and hygiene must have ONE
            // view of what belongs to the zone.
            $iterator = $zone->iterator(unreadable: $unreadable);
        } catch (Throwable $e) {
            $this->issues[] = sprintf('zone "%s" cannot be walked: %s', $zone->name, $e->getMessage());
            $context->issues?->markIncomplete($this->id());

            return;
        }

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            // isLink() BEFORE isDir(): isDir() follows the link (stat, not
            // lstat), so a symlink to a directory would be classified as a directory and lost
            // right there, before any matcher saw it; that is how
            // `uploads.symlink-in-upload-zone` silently disappeared. A link is
            // a candidate in itself (both for a file and for a directory), not a directory to descend
            // into (there is no descent into it anyway, without FOLLOW_SYMLINKS).
            if ($file->isLink()) {
                yield $file;

                continue;
            }

            if ($file->isDir()) {
                continue;
            }

            yield $file;
        }

        $context->issues?->addUnreadable($this->id(), $zone->name, $unreadable, $context->base);
    }
}
