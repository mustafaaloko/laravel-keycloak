<?php

namespace Aloko\Keycloak\Tests;

use Aloko\Keycloak\KeycloakServiceProvider;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

class TestCase extends \Orchestra\Testbench\TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * @param \Illuminate\Foundation\Application $app
     *
     * @return string[]
     */
    protected function getPackageProviders($app)
    {
        return [
            KeycloakServiceProvider::class
        ];
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function defineEnvironment($app)
    {
        $app['config']->set('keycloak', [
            'server_url' => 'https://auth-server.com',
            'realm' => 'test-realm',
            'client_id' => 'test-client-id',
            'client_secret' => 'test-client-secret',
            'redirect_uri' => '/auth/callback',
            'realm_encryption_algo' => 'RS256',
            'realm_public_key' => 'a-public-key',
        ]);

        $app['config']->set('auth.guards.web', [
            'driver' => 'keycloak',
            'provider' => 'users'
        ]);

        $app['config']->set('auth.defaults', [
            'guard' => 'web',
            'passwords' => 'users'
        ]);
    }
}
