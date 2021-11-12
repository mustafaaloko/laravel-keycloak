<?php

namespace Aloko\Keycloak\Tests\Guard;

use Aloko\Keycloak\KeycloakProvider;
use League\OAuth2\Client\Token\AccessToken;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Mockery as m;

class KeycloakProviderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testItCreatesAKeycloakProviderInstanceFromConfig()
    {
        $instance = KeycloakProvider::createFromConfig($this->sampleConfig());

        $this->assertInstanceOf(KeycloakProvider::class, $instance);
        $this->assertInstanceOf(Keycloak::class, $instance);
    }

    public function testItCanFetchToken()
    {
        $token = m::mock(AccessToken::class);
        $keycloak = m::mock(KeycloakProvider::class.'[getAccessToken]');
        $keycloak->shouldReceive('getAccessToken')->with('authorization_code', ['code' => 'foo'])->andReturn($token);

        $this->assertSame($token, $keycloak->fetchToken('foo'));
    }

    public function testItCanRefreshToken()
    {
        $token = m::mock(AccessToken::class);
        $keycloak = m::mock(KeycloakProvider::class.'[getAccessToken]');
        $keycloak->shouldReceive('getAccessToken')->with('refresh_token', ['refresh_token' => 'foo'])->andReturn($token);

        $this->assertSame($token, $keycloak->refreshToken('foo'));
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testItCanGenerateTheLogoutUrl()
    {
        $parent = m::mock('overload:'.Keycloak::class);
        $parent->shouldReceive('getLogoutUrl')->once()->with([
            'redirect_uri' => '/auth/logout/callback'
        ])->andReturn('foo');

        $keycloak = KeycloakProvider::createFromConfig($this->sampleConfig());
        $keycloak->getLogoutUrl();
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutRedirectUriCanBeOverridden()
    {
        $parent = m::mock('overload:'.Keycloak::class);
        $parent->shouldReceive('getLogoutUrl')->once()->with(['redirect_uri' => 'foo'])->andReturn('foo');

        $keycloak = KeycloakProvider::createFromConfig($this->sampleConfig());
        $keycloak->getLogoutUrl(['redirect_uri' => 'foo']);
    }

    protected function sampleConfig(): array
    {
        return [
            'server_url' => 'test-value',
            'realm' => 'test-value',
            'client_id' => 'test-value',
            'client_secret' => 'test-value',
            'redirect_uri' => 'test-value',
            'realm_encryption_algo' => 'test-value',
            'realm_public_key' => 'test-value'
        ];
    }
}
