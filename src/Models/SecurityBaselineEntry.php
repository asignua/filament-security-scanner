<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Models;

use Asignua\FilamentSecurityScanner\SecurityScanner;
use Illuminate\Database\Eloquent\Model;

/**
 * A row of the hash snapshot of a zone git cannot see.
 *
 * The snapshot covers only what git does NOT track — first of all vendor/ (16 thousand
 * files, rebuilt on every deploy). Tracked code needs no baseline:
 * git compares against a remote commit the attacker does not control, so it
 * cannot be poisoned by taking the "reference" after the substitution.
 *
 * The table has no timestamps: a row is immutable by construction, and the snapshot time is shared
 * by the whole snapshot and stored in taken_at.
 *
 * @property int $id
 * @property string $snapshot_id
 * @property string $zone
 * @property string $path
 * @property string $path_hash
 * @property string $content_hash
 * @property string $hash_algo
 * @property int $size
 * @property int $mtime
 * @property int|null $mode
 * @property bool $complete
 * @property \Illuminate\Support\Carbon|null $taken_at
 *
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry newModelQuery()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry newQuery()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry query()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereComplete($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereContentHash($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereHashAlgo($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereId($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereMode($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereMtime($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry wherePath($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry wherePathHash($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereSize($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereSnapshotId($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereTakenAt($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityBaselineEntry whereZone($value)
 *
 * @mixin \Eloquent
 */
class SecurityBaselineEntry extends Model
{
    public $timestamps = false;

    protected $guarded = ['*'];

    public function getTable(): string
    {
        return SecurityScanner::table('security_baseline');
    }

    protected function casts(): array
    {
        return [
            'complete' => 'boolean',
            'taken_at' => 'datetime',
        ];
    }
}
