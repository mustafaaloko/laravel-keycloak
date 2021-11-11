<?php

namespace Aloko\Keycloak;

use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

class KeycloakServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/config.php' => config_path('keycloak.php'),
            ], 'config');
        }
    }

    /**
     * Register the application services.
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'keycloak');

        $this->app['auth']->extend('keycloak', function ($app, $name, array $config) {
            return new KeycloakGuard(
                $name,
                new KeycloakManager(
                    $this->config(),
                    $this->getJwtConfiguration()
                ),
                $app['auth']->createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );
        });
    }

    protected function getJwtConfiguration(): Configuration
    {
        return Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText(''),
            InMemory::plainText($this->config()['realm_public_key'])
        );
    }

    protected function config()
    {
        return config('keycloak');
    }
}
