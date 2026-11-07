<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests\Feature;

use Asignua\FilamentSecurityScanner\Telegram;
use Asignua\FilamentSecurityScanner\Tests\TestCase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Mockery;

class TelegramRedactionTest extends TestCase
{
    public function test_the_bot_token_never_reaches_the_log(): void
    {
        config([
            'security-scanner.telegram.enabled' => true,
            'security-scanner.telegram.token' => '123456:SECRET-TOKEN_abc',
            'security-scanner.telegram.chat_id' => '42',
        ]);
        Http::fake(static function (): never {
            throw new ConnectionException('cURL error 28: Operation timed out for https://api.telegram.org/bot123456:SECRET-TOKEN_abc/sendMessage');
        });

        $logged = [];
        Log::shouldReceive('warning')->andReturnUsing(static function (string $message) use (&$logged): void {
            $logged[] = $message;
        });
        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('debug', 'info', 'error')->andReturnNull();

        $this->assertFalse(Telegram::send('hello'));

        $this->assertNotSame([], $logged);

        foreach ($logged as $message) {
            $this->assertStringNotContainsString('SECRET-TOKEN', $message);
            $this->assertStringContainsString('/bot<redacted>/', $message);
        }
        Mockery::close();
    }
}
