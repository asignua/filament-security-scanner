<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Intrusion-trace scanner for the file system: runs, findings, baseline.
 *
 * The three tables are born together, so there is one migration
 * rather than one per table.
 *
 * RUNS are not for show. Without them a SILENT FAILURE is invisible: "the scanner did not
 * run for five days" looks exactly like "all clean", and this is the
 * most dangerous failure mode of the whole subsystem. The row is written AT THE START with
 * status `running` — a run killed by OOM must leave a trace.
 *
 * The finding FINGERPRINT = sha256(rule_id | scanner | path | content hash?).
 * The content hash being part of it means: an untouched file every night gives the SAME row and
 * only times_seen++, with no new alarm; the same path with changed contents gives
 * a NEW finding — because a shell that rewrites itself is genuinely a new event.
 * The unique index makes the daily upsert idempotent and removes the race between the nightly
 * run and the upload-triggered run.
 *
 * SEVERITY is stored twice: as a string for humans and as a weight for SQL. `WHERE
 * severity_weight >= 80` can use an index, `WHERE severity IN (...)` cannot. The
 * same trick as in Enums\Role::weight().
 *
 * PATH HAS NO INDEX — deliberately. Findings number in the tens, not millions; besides, under
 * utf8mb4 a full-length path index is impossible (>3072 bytes). In baseline,
 * where there are thousands of rows, uniqueness is held by path_hash, not by the path itself.
 *
 * NO FK TO USERS (as in the mail log and visitors tables): the users table
 * belongs to the host, and an audit record must survive user deletion — the
 * denormalized status_by_label sits next to it for that.
 *
 * An FK BETWEEN OUR OWN tables, on the contrary, is appropriate: both are ours, the migration
 * order is guaranteed.
 *
 * Tables are `security_scans` / `security_findings` / `security_baseline`
 * (with the host prefix, `security-scanner.tables.prefix`). Every
 * `Schema::create` is wrapped in `hasTable()`: on installs of the previous host-integrated version of the
 * scanner the tables already exist under the legacy name `ee_security_*`, and the migration must stay
 * idempotent rather than fail on duplicates.
 */
return new class extends Migration
{
    private function prefix(): string
    {
        return (string) config('security-scanner.tables.prefix', '');
    }

    public function up(): void
    {
        if (!Schema::hasTable($this->prefix().'security_scans')) {
            Schema::create($this->prefix().'security_scans', function (Blueprint $table): void {
                $table->id();
                $table->ulid('ulid')->unique();
                $table->string('trigger', 16)->index();          // schedule|manual|upload|deploy
                $table->string('status', 16);                    // running|ok|findings|partial|failed
                $table->json('scanners')->nullable();            // per-scanner status/duration/counters
                $table->string('registry_version', 64)->nullable();
                $table->string('release', 64)->nullable();       // git SHA at the time of the run
                $table->unsignedInteger('files_scanned')->default(0);
                $table->unsignedBigInteger('bytes_scanned')->default(0);
                $table->unsignedInteger('duration_ms')->default(0);
                $table->unsignedInteger('findings_new')->default(0);
                $table->unsignedInteger('findings_total')->default(0);
                $table->text('error')->nullable();
                $table->timestamp('started_at')->nullable();
                $table->timestamp('finished_at')->nullable();
                $table->timestamps();

                // The composite also covers filtering by status alone (index prefix).
                $table->index(['status', 'created_at']);
            });
        }

        if (!Schema::hasTable($this->prefix().'security_findings')) {
            Schema::create($this->prefix().'security_findings', function (Blueprint $table): void {
                $table->id();
                $table->ulid('ulid')->unique();
                $table->char('fingerprint', 64)->unique();

                $table->foreignId('first_scan_id')->nullable()
                    ->constrained($this->prefix().'security_scans')->nullOnDelete();
                $table->foreignId('last_scan_id')->nullable()
                    ->constrained($this->prefix().'security_scans')->nullOnDelete();

                $table->string('scanner', 32);
                $table->string('rule_id', 64);
                $table->string('severity', 16);
                $table->unsignedTinyInteger('severity_weight');
                $table->string('zone', 64)->nullable();
                $table->string('zone_kind', 32)->nullable()->index();
                $table->string('disk', 32)->nullable();
                $table->string('path', 400)->nullable();
                $table->string('title', 255)->nullable();
                $table->json('evidence')->nullable();
                $table->unsignedBigInteger('size')->nullable();
                $table->unsignedBigInteger('file_mtime')->nullable();
                // string, not char: PostgreSQL pads char(n) with blanks, and xxh128 is only 32 chars.
                $table->string('content_hash', 64)->nullable();
                $table->string('mime', 128)->nullable();

                $table->string('status', 16)->default('new');
                $table->timestamp('status_changed_at')->nullable();
                $table->unsignedBigInteger('status_by_id')->nullable()->index();
                $table->string('status_by_label')->nullable();
                $table->text('status_note')->nullable();

                $table->string('quarantine_path', 400)->nullable();
                $table->timestamp('quarantined_at')->nullable();
                $table->boolean('quarantine_auto')->default(false);

                $table->unsignedInteger('times_seen')->default(1);
                $table->timestamp('first_seen_at')->nullable();
                $table->timestamp('last_seen_at')->nullable();

                // The stamp gets ITS OWN cell per channel: the three channels have different failure
                // modes (SMTP is down / Telegram returned 429 / the panel always works), and
                // one shared flag would give either duplicates or silent losses.
                $table->json('notified_channels')->nullable();
                $table->timestamp('notified_at')->nullable()->index();

                $table->string('registry_source', 16)->nullable();
                $table->string('registry_version', 64)->nullable();

                $table->timestamps();

                $table->index(['status', 'severity_weight']);
                $table->index(['scanner', 'rule_id']);
                $table->index(['status', 'last_seen_at']);
            });
        }

        if (!Schema::hasTable($this->prefix().'security_baseline')) {
            Schema::create($this->prefix().'security_baseline', function (Blueprint $table): void {
                $table->id();
                $table->char('snapshot_id', 26)->index();
                $table->string('zone', 64)->index();
                $table->string('path', 400);
                $table->char('path_hash', 64);
                $table->string('content_hash', 64);
                // The algorithm is in the row: changing it must force a RE-TAKE of the snapshot rather
                // than report 16 thousand "modifications".
                $table->string('hash_algo', 16)->default('xxh128');
                $table->unsignedBigInteger('size')->default(0);
                $table->unsignedBigInteger('mtime')->default(0);
                $table->unsignedSmallInteger('mode')->nullable();
                // The snapshot is written as false and switched to true only on successful
                // completion: a crash mid-hashing leaves an incomplete snapshot, which is
                // ignored and pruned rather than passing itself off as complete.
                $table->boolean('complete')->default(false);
                $table->timestamp('taken_at')->nullable();

                $table->unique(['snapshot_id', 'path_hash']);
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists($this->prefix().'security_baseline');
        Schema::dropIfExists($this->prefix().'security_findings');
        Schema::dropIfExists($this->prefix().'security_scans');
    }
};
