<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Models;

use Asignua\FilamentSecurityScanner\Casts\UnescapedJson;
use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\SecurityScanner;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A scanner finding, deduplicated by fingerprint.
 *
 * One row = one ENTITY of a problem, not one occurrence of it. A repeated run
 * only bumps times_seen and last_seen_at; a new alarm is born only
 * when the fingerprint changes — i.e. when the file contents at the same
 * path changed. A shell that rewrites itself is genuinely a new event; the same
 * untouched file every night is not.
 *
 * severity is stored twice: as a string for humans and as a weight for SQL. BOTH must be written,
 * otherwise filters and notification gates will diverge from what the table shows.
 *
 * @property int $id
 * @property string $ulid
 * @property string $fingerprint
 * @property int|null $first_scan_id
 * @property int|null $last_scan_id
 * @property string $scanner
 * @property string $rule_id
 * @property SecuritySeverity $severity
 * @property int $severity_weight
 * @property string|null $zone
 * @property SecurityZoneKind|null $zone_kind
 * @property string|null $disk
 * @property string|null $path
 * @property string|null $title
 * @property array<int, array<string, mixed>>|null $evidence
 * @property int|null $size
 * @property int|null $file_mtime
 * @property string|null $content_hash
 * @property string|null $mime
 * @property SecurityFindingStatus $status
 * @property \Illuminate\Support\Carbon|null $status_changed_at
 * @property int|null $status_by_id
 * @property string|null $status_by_label
 * @property string|null $status_note
 * @property string|null $quarantine_path
 * @property \Illuminate\Support\Carbon|null $quarantined_at
 * @property bool $quarantine_auto
 * @property int $times_seen
 * @property \Illuminate\Support\Carbon|null $first_seen_at
 * @property \Illuminate\Support\Carbon|null $last_seen_at
 * @property array<string, mixed>|null $notified_channels
 * @property \Illuminate\Support\Carbon|null $notified_at
 * @property string|null $registry_source
 * @property string|null $registry_version
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 * @property-read SecurityScan|null $firstScan
 * @property-read SecurityScan|null $lastScan
 *
 * @method static Builder<static>|SecurityFinding newModelQuery()
 * @method static Builder<static>|SecurityFinding newQuery()
 * @method static Builder<static>|SecurityFinding notNotifiedVia(string $channel)
 * @method static Builder<static>|SecurityFinding open()
 * @method static Builder<static>|SecurityFinding query()
 * @method static Builder<static>|SecurityFinding whereContentHash($value)
 * @method static Builder<static>|SecurityFinding whereCreatedAt($value)
 * @method static Builder<static>|SecurityFinding whereDisk($value)
 * @method static Builder<static>|SecurityFinding whereEvidence($value)
 * @method static Builder<static>|SecurityFinding whereFileMtime($value)
 * @method static Builder<static>|SecurityFinding whereFingerprint($value)
 * @method static Builder<static>|SecurityFinding whereFirstScanId($value)
 * @method static Builder<static>|SecurityFinding whereFirstSeenAt($value)
 * @method static Builder<static>|SecurityFinding whereId($value)
 * @method static Builder<static>|SecurityFinding whereLastScanId($value)
 * @method static Builder<static>|SecurityFinding whereLastSeenAt($value)
 * @method static Builder<static>|SecurityFinding whereMime($value)
 * @method static Builder<static>|SecurityFinding whereNotifiedAt($value)
 * @method static Builder<static>|SecurityFinding whereNotifiedChannels($value)
 * @method static Builder<static>|SecurityFinding wherePath($value)
 * @method static Builder<static>|SecurityFinding whereQuarantineAuto($value)
 * @method static Builder<static>|SecurityFinding whereQuarantinePath($value)
 * @method static Builder<static>|SecurityFinding whereQuarantinedAt($value)
 * @method static Builder<static>|SecurityFinding whereRegistrySource($value)
 * @method static Builder<static>|SecurityFinding whereRegistryVersion($value)
 * @method static Builder<static>|SecurityFinding whereRuleId($value)
 * @method static Builder<static>|SecurityFinding whereScanner($value)
 * @method static Builder<static>|SecurityFinding whereSeverity($value)
 * @method static Builder<static>|SecurityFinding whereSeverityWeight($value)
 * @method static Builder<static>|SecurityFinding whereSize($value)
 * @method static Builder<static>|SecurityFinding whereStatus($value)
 * @method static Builder<static>|SecurityFinding whereStatusById($value)
 * @method static Builder<static>|SecurityFinding whereStatusByLabel($value)
 * @method static Builder<static>|SecurityFinding whereStatusChangedAt($value)
 * @method static Builder<static>|SecurityFinding whereStatusNote($value)
 * @method static Builder<static>|SecurityFinding whereTimesSeen($value)
 * @method static Builder<static>|SecurityFinding whereTitle($value)
 * @method static Builder<static>|SecurityFinding whereUlid($value)
 * @method static Builder<static>|SecurityFinding whereUpdatedAt($value)
 * @method static Builder<static>|SecurityFinding whereZone($value)
 * @method static Builder<static>|SecurityFinding whereZoneKind($value)
 *
 * @mixin \Eloquent
 */
class SecurityFinding extends Model
{
    protected $guarded = ['*'];

    public function getTable(): string
    {
        return SecurityScanner::table('security_findings');
    }

    /**
     * @return BelongsTo<SecurityScan, $this>
     */
    public function firstScan(): BelongsTo
    {
        return $this->belongsTo(SecurityScan::class, 'first_scan_id');
    }

    /**
     * @return BelongsTo<SecurityScan, $this>
     */
    public function lastScan(): BelongsTo
    {
        return $this->belongsTo(SecurityScan::class, 'last_scan_id');
    }

    /**
     * Findings that still need human attention.
     *
     * @param Builder<SecurityFinding> $query
     *
     * @return Builder<SecurityFinding>
     */
    public function scopeOpen(Builder $query): Builder
    {
        return $query->whereIn('status', [
            SecurityFindingStatus::New->value,
            SecurityFindingStatus::Acknowledged->value,
        ]);
    }

    /**
     * Findings not yet notified on the given channel.
     *
     * The gate is exactly per channel cell, not per a shared notified_at: channels
     * fail independently of each other.
     *
     * AUTO-quarantine notifies too: it switches the finding to `quarantined` in the same
     * run, BEFORE the notification listener, so a "new only" gate made a confirmed
     * intrusion invisible to all channels. Manual quarantine does not: it was done by a
     * human who is already looking at the finding.
     *
     * @param Builder<SecurityFinding> $query
     *
     * @return Builder<SecurityFinding>
     */
    public function scopeNotNotifiedVia(Builder $query, string $channel): Builder
    {
        return $query
            ->where(function (Builder $q): void {
                $q->where('status', SecurityFindingStatus::New->value)
                    ->orWhere(function (Builder $q): void {
                        $q->where('status', SecurityFindingStatus::Quarantined->value)
                            ->where('quarantine_auto', true);
                    });
            })
            ->where(function (Builder $q) use ($channel): void {
                $q->whereNull('notified_channels')
                    ->orWhereNull('notified_channels->'.$channel);
            });
    }

    protected function casts(): array
    {
        return [
            'evidence' => UnescapedJson::class,
            'notified_channels' => UnescapedJson::class,
            'severity' => SecuritySeverity::class,
            'status' => SecurityFindingStatus::class,
            'zone_kind' => SecurityZoneKind::class,
            'quarantine_auto' => 'boolean',
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'status_changed_at' => 'datetime',
            'quarantined_at' => 'datetime',
            'notified_at' => 'datetime',
        ];
    }
}
