<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Models;

use Asignua\FilamentSecurityScanner\Casts\UnescapedJson;
use Asignua\FilamentSecurityScanner\Enums\SecurityScanStatus;
use Asignua\FilamentSecurityScanner\Enums\SecurityScanTrigger;
use Asignua\FilamentSecurityScanner\SecurityScanner;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * One run of the intrusion-trace scanner.
 *
 * Records are created by {@see \Asignua\FilamentSecurityScanner\Scanning\ScanRunner}, not by a form, so
 * there is no DTO/repository — a record is written by assigning properties. Mass assignment
 * is disabled, so ::create([...]) would silently write nothing.
 *
 * The row appears AT THE START with status `running`. That is the whole point of the table:
 * a run killed by OOM or a timeout must leave a trace, because a scanner that silently did not
 * run looks exactly like "all clean".
 *
 * @property int $id
 * @property string $ulid
 * @property SecurityScanTrigger $trigger
 * @property SecurityScanStatus $status
 * @property array<string, mixed>|null $scanners
 * @property string|null $registry_version
 * @property string|null $release
 * @property int $files_scanned
 * @property int $bytes_scanned
 * @property int $duration_ms
 * @property int $findings_new
 * @property int $findings_total
 * @property string|null $error
 * @property \Illuminate\Support\Carbon|null $started_at
 * @property \Illuminate\Support\Carbon|null $finished_at
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 * @property-read \Illuminate\Database\Eloquent\Collection<int, SecurityFinding> $findings
 * @property-read int|null $findings_count
 *
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan newModelQuery()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan newQuery()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan query()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereBytesScanned($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereCreatedAt($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereDurationMs($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereError($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereFilesScanned($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereFindingsNew($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereFindingsTotal($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereFinishedAt($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereId($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereRegistryVersion($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereRelease($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereScanners($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereStartedAt($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereStatus($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereTrigger($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereUlid($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|SecurityScan whereUpdatedAt($value)
 *
 * @mixin \Eloquent
 */
class SecurityScan extends Model
{
    protected $guarded = ['*'];

    public function getTable(): string
    {
        return SecurityScanner::table('security_scans');
    }

    /**
     * @return HasMany<SecurityFinding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(SecurityFinding::class, 'last_scan_id');
    }

    /**
     * Whether the run covered the zones fully enough that unseen findings can be
     * considered gone. Delegates to the enum — one rule for the whole subsystem.
     */
    public function closesFindings(): bool
    {
        return $this->status->closesFindings();
    }

    protected function casts(): array
    {
        return [
            // UnescapedJson, not the stock 'array': otherwise non-ASCII scanner
            // labels would land in the DB as \u0414\u043e..., and
            // JsonColumnEncodingTest would fail.
            'scanners' => UnescapedJson::class,
            'status' => SecurityScanStatus::class,
            'trigger' => SecurityScanTrigger::class,
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }
}
