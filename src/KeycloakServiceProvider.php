<?php

namespace Aloko\Keycloak;

use Aloko\Keycloak\Token\TokenManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

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

        $this->app['auth']->extend('keycloak', function (Application $app, $name, array $config) {
            return $this->buildKeycloakGuard($app, $name, $config);
        });
    }

    protected function buildKeycloakGuard(Application $app, $name, array $config): KeycloakGuard
    {
        $guard = new KeycloakGuard(
            $name,
            new KeycloakManager($this->keycloakConfig(), $this->buildTokenManager()),
            $app['auth']->createUserProvider($config['provider'] ?? null),
            $app['session.store'],
            $app['request']
        );

        $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

        return $guard;
    }

    protected function buildTokenManager(): TokenManager
    {
        return new TokenManager($this->buildJwtConfig());
    }

    protected function buildJwtConfig(): Configuration
    {
        return Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText(''),
            InMemory::plainText($this->realmPublicKey())
        );
    }

    protected function keycloakConfig($key = null)
    {
        return config(is_null($key) ? 'keycloak' : 'keycloak.'.$key);
    }

    protected function realmPublicKey(): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . wordwrap($this->keycloakConfig('realm_public_key'), 64, "\n", true) . "\n-----END PUBLIC KEY-----";
    }
}
