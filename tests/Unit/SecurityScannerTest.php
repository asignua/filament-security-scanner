<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Unit;

use Asignua\FilamentSecurityScanner\SecurityScanner;
use Asignua\FilamentSecurityScanner\Tests\PureTestCase;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;

class SecurityScannerTest extends PureTestCase
{
    public function test_table_name_carries_the_configured_prefix(): void
    {
        $this->assertSame('security_findings', SecurityScanner::table('security_findings'));

        config(['security-scanner.tables.prefix' => 'ee_']);
        $this->assertSame('ee_security_findings', SecurityScanner::table('security_findings'));
    }

    public function test_without_a_resolver_nobody_is_notified(): void
    {
        $this->assertCount(0, SecurityScanner::notifyUsers());
    }

    public function test_the_resolver_supplies_recipients_and_flush_forgets_it(): void
    {
        SecurityScanner::notifyUsersUsing(static fn (): Collection => self::fakeUsers());
        $this->assertCount(2, SecurityScanner::notifyUsers());

        SecurityScanner::flush();
        $this->assertCount(0, SecurityScanner::notifyUsers());
    }

    public function test_user_model_comes_from_the_auth_provider(): void
    {
        $this->assertNull(SecurityScanner::userModel());

        config(['auth.providers.users.model' => self::class]);
        $this->assertSame(self::class, SecurityScanner::userModel());
    }

    /**
     * @return Collection<int, Model>
     */
    private static function fakeUsers(): Collection
    {
        return new Collection([
            self::asModel(new class extends Model {}),
            self::asModel(new class extends Model {}),
        ]);
    }

    /**
     * The abstract `Model` cannot be instantiated directly (the test wants a real
     * model instance, not a mock): an anonymous subclass narrows the array element
     * type, and Collection infers generics from it. We pass the instance
     * through a `Model` type parameter so the array sees the base type.
     */
    private static function asModel(Model $model): Model
    {
        return $model;
    }
}
