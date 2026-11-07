<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Scanning;

use Asignua\FilamentSecurityScanner\Models\SecurityBaselineEntry;
use Generator;
use Illuminate\Support\Str;
use SplFileInfo;
use Throwable;

/**
 * A hash snapshot of a zone, for what git does not see.
 *
 * It covers primarily `vendor/`: 16 thousand files, under `.gitignore`, and
 * rebuilt by `composer install` on every deploy. We compare it NOT with a
 * release or with git, but with the current snapshot: between two deploys vendor is unchanged
 * by construction, so any divergence is either an intrusion or a manual
 * hotfix, and we need to know about both.
 *
 * That is why the snapshot is a DEPLOY step, not a schedule item: taken right after
 * `composer install`, it gives zero noise until the next deploy.
 *
 * `complete` switches to `true` ONLY after successful completion. A crash
 * in the middle of hashing leaves an incomplete snapshot, which is ignored and cleaned up, not
 * passed off as the reference.
 *
 * The algorithm is stored in a string: changing it must force a re-snapshot,
 * not report 16 thousand "modifications".
 */
final class BaselineSnapshot
{
    public const string PREFERRED_ALGO = 'xxh128';

    public static function algo(): string
    {
        // xxh128 is roughly ten times faster than sha256, and cryptographic strength is
        // not needed here: the snapshot protects against ACCIDENTAL and crude tampering, and
        // against targeted tampering it is protected not by the hash but by the fact that the attacker
        // does not control the moment the snapshot is taken.
        return in_array(self::PREFERRED_ALGO, hash_algos(), true) ? self::PREFERRED_ALGO : 'sha256';
    }

    /**
     * Takes a zone snapshot. Returns snapshot_id.
     *
     * @param list<string> $allowlist
     */
    public static function take(Zone $zone, string $base, array $allowlist = []): string
    {
        $snapshotId = (string) Str::ulid();
        $algo = self::algo();
        $takenAt = now();
        $batch = [];

        foreach (self::walk($zone) as $file) {
            $relative = PathNormalizer::relative($file->getPathname(), $base);

            foreach ($allowlist as $pattern) {
                if (PathNormalizer::matchesGlob($relative, $pattern)) {
                    continue 2;
                }
            }

            $hash = @hash_file($algo, $file->getPathname());

            if ($hash === false) {
                continue;
            }

            $batch[] = [
                'snapshot_id' => $snapshotId,
                'zone' => $zone->name,
                'path' => $relative,
                'path_hash' => hash('sha256', $relative),
                'content_hash' => $hash,
                'hash_algo' => $algo,
                'size' => (int) @$file->getSize(),
                'mtime' => (int) @$file->getMTime(),
                'mode' => null,
                'complete' => false,
                'taken_at' => $takenAt,
            ];

            if (count($batch) >= 500) {
                SecurityBaselineEntry::query()->insert($batch);
                $batch = [];
            }
        }

        if ($batch !== []) {
            SecurityBaselineEntry::query()->insert($batch);
        }

        SecurityBaselineEntry::query()
            ->where('snapshot_id', $snapshotId)
            ->update(['complete' => true]);

        return $snapshotId;
    }

    /**
     * The latest COMPLETE snapshot of the zone.
     */
    public static function latestComplete(string $zone): ?string
    {
        /** @var string|null $id */
        $id = SecurityBaselineEntry::query()
            ->where('zone', $zone)
            ->where('complete', true)
            ->orderByDesc('id')
            ->value('snapshot_id');

        return $id;
    }

    /**
     * Removes everything except the last two complete zone snapshots, and all incomplete ones.
     */
    public static function prune(string $zone, int $keep = 2): int
    {
        /** @var list<string> $keepIds */
        $keepIds = SecurityBaselineEntry::query()
            ->select('snapshot_id')
            ->where('zone', $zone)
            ->where('complete', true)
            ->groupBy('snapshot_id')
            ->orderByRaw('MAX(id) DESC')
            ->limit($keep)
            ->pluck('snapshot_id')
            ->all();

        $query = SecurityBaselineEntry::query()->where('zone', $zone);

        if ($keepIds !== []) {
            $query->whereNotIn('snapshot_id', $keepIds);
        }

        return $query->delete();
    }

    /**
     * @return Generator<SplFileInfo>
     */
    public static function walk(Zone $zone): Generator
    {
        try {
            $iterator = $zone->iterator();
        } catch (Throwable) {
            return;
        }

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->isDir() || $file->isLink()) {
                continue;
            }

            yield $file;
        }
    }
}
