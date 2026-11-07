<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Concerns;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Illuminate\Support\Str;

trait MakesFindings
{
    /**
     * @param array<string, mixed> $attributes
     */
    protected function makeFinding(string $path = 'storage/app/public/uploads/shell.php', array $attributes = []): SecurityFinding
    {
        $finding = new SecurityFinding;
        $finding->forceFill(array_merge([
            'ulid' => (string) Str::ulid(),
            'fingerprint' => Finding::fingerprintFor('uploads.executable-extension', 'uploads', $path, null),
            'scanner' => 'uploads',
            'rule_id' => 'uploads.executable-extension',
            'severity' => SecuritySeverity::High,
            'severity_weight' => SecuritySeverity::High->weight(),
            'zone' => 'storage_public',
            'zone_kind' => SecurityZoneKind::UploadWeb,
            'path' => $path,
            'title' => 'security-scanner::rules.Executable file in an upload directory',
            'status' => SecurityFindingStatus::New,
            'times_seen' => 1,
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ], $attributes))->save();

        return $finding;
    }
}
