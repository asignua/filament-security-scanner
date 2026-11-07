<?php

declare(strict_types=1);

namespace Asignua\FilamentSecurityScanner\Tests;

use Asignua\FilamentSecurityScanner\SecurityScanner;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * Light base for the application-independent tests: just a container plus a
 * config repository so that the config() helper works. Each test sets the
 * security-scanner.* keys it needs through config([...]). There is deliberately
 * no translator or database here; anything that needs the application extends
 * {@see TestCase} instead.
 */
abstract class PureTestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $app = new Container;
        Container::setInstance($app);
        $app->instance('config', new Repository);
        SecurityScanner::flush();
    }

    protected function tearDown(): void
    {
        SecurityScanner::flush();
        Container::setInstance(null);

        parent::tearDown();
    }
}
