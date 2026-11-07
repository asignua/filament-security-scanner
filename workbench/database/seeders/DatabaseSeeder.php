<?php

declare(strict_types=1);

namespace Workbench\Database\Seeders;

use Asignua\FilamentSecurityScanner\Enums\SecurityFindingStatus;
use Asignua\FilamentSecurityScanner\Enums\SecuritySeverity;
use Asignua\FilamentSecurityScanner\Enums\SecurityZoneKind;
use Asignua\FilamentSecurityScanner\Models\SecurityFinding;
use Asignua\FilamentSecurityScanner\Scanning\Finding;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Workbench\App\Models\User;

/**
 * Demo data. Two kinds of findings:
 *  - REAL ones: inert files are dropped into the public upload zone and a genuine
 *    scan creates the findings, so quarantine and restore move a real file;
 *  - hand-written rows for the other statuses, so the list shows every badge.
 * The files are harmless: the "shell" only echoes a word and the polyglot is a
 * few image bytes followed by an echo of a word.
 */
class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        User::query()->firstOrCreate(['email' => 'emma@example.com'], ['name' => 'Emma', 'password' => 'password', 'is_active' => true]);

        $dir = storage_path('app/public/uploads');
        File::ensureDirectoryExists($dir);
        File::put($dir.'/invoice-copy.php', '<?php echo "neutralized"; ?>'."\n");
        File::put($dir.'/holiday.jpg', "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00".str_repeat("\x00", 64).'<?php echo "neutralized"; ?>');
        File::put($dir.'/.htaccess', "php_value auto_prepend_file x\n");

        Artisan::call('security:scan', ['--trigger' => 'manual', '--fail-on' => 'none']);

        $this->row('uploads.executable-extension', 'uploads', 'storage/app/public/old/legacy-form.php', SecuritySeverity::High, SecurityFindingStatus::Acknowledged);
        $this->row('obf.php-after-binary', 'obfuscation', 'storage/app/public/old/banner.png', SecuritySeverity::Critical, SecurityFindingStatus::Ignored);
        $this->row('code.modified-file', 'code', 'app/Http/Controllers/HomeController.php', SecuritySeverity::Medium, SecurityFindingStatus::Resolved);
        $this->row('hygiene.debug-enabled', 'hygiene', '.env', SecuritySeverity::Low, SecurityFindingStatus::New);
    }

    private function row(string $rule, string $scanner, string $path, SecuritySeverity $severity, SecurityFindingStatus $status): void
    {
        $fingerprint = Finding::fingerprintFor($rule, $scanner, $path, null);

        if (SecurityFinding::query()->where('fingerprint', $fingerprint)->exists()) {
            return;
        }

        $finding = new SecurityFinding;
        $finding->forceFill([
            'ulid' => (string) Str::ulid(),
            'fingerprint' => $fingerprint,
            'scanner' => $scanner,
            'rule_id' => $rule,
            'severity' => $severity,
            'severity_weight' => $severity->weight(),
            'zone' => 'demo',
            'zone_kind' => SecurityZoneKind::UploadWeb,
            'path' => $path,
            'title' => 'security-scanner::rules.Executable file in an upload directory',
            'status' => $status,
            'times_seen' => 3,
            'first_seen_at' => now()->subDays(5),
            'last_seen_at' => now()->subDay(),
        ])->save();
    }
}
