<?php

namespace Aloko\Keycloak\Tests;

use Aloko\Keycloak\KeycloakGuard;

class ServiceProviderTest extends TestCase
{
    /** @test */
    public function it_returns_keycloak_as_the_default_guard_based_on_configuration()
    {
        $this->assertInstanceOf(KeycloakGuard::class, $this->app['auth']->guard());
    }
}
