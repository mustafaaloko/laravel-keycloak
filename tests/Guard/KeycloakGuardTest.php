<?php

namespace Aloko\Keycloak\Tests\Guard;

use Aloko\Keycloak\Exceptions\FetchAccessTokenFailedException;
use Aloko\Keycloak\Exceptions\RelatedUserNotFoundException;
use Aloko\Keycloak\Exceptions\StateMismatchException;
use Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailed;
use Aloko\Keycloak\KeycloakManager;
use Aloko\Keycloak\KeycloakGuard;
use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class KeycloakGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testItReturnsRedirectResponseOnAttempt()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));
        $keycloak->shouldReceive('getAuthorizationUrl')->once()->andReturn('https://foo.com');
        $keycloak->shouldReceive('getState')->andReturn('biz')->once();
        $session->shouldReceive('put')->with('oauth2state', 'biz')->once();
        $session->shouldReceive('save')->once();

        $redirect = $guard->attempt();

        $this->assertInstanceOf(RedirectResponse::class, $redirect);
        $this->assertEquals('https://foo.com', $redirect->getTargetUrl());
    }

    public function testCallingPrepareSetsSessionProperlyAndReturnsSelf()
    {
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));
        $keycloak->shouldReceive('getAuthorizationUrl')->once()->andReturn('https://foo.com');
        $keycloak->shouldReceive('getState')->andReturn('biz')->once();

        $res = $guard->prepare();

        $session->shouldHaveReceived('put')->with('oauth2state', 'biz')->once();
        $session->shouldHaveReceived('save')->once();
        $this->assertInstanceOf(KeycloakGuard::class, $res);
    }

    public function testItReturnsAuthorizationUrl()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));
        $keycloak->shouldReceive('getAuthorizationUrl')->once()->andReturn('https://foo.com');
        $keycloak->shouldReceive('getState')->andReturn('biz')->once();
        $session->makePartial()->shouldReceive('put')->with('oauth2state', 'biz')->once();
        $session->shouldReceive('save')->once();

        $url = $guard->prepare()->url();

        $this->assertEquals('https://foo.com', $url);
    }

    public function testItThrowsExceptionIfUrlIsCalledWithoutPrepare()
    {
        $this->expectException(\BadMethodCallException::class);

        [$keycloak, $provider, $session] = $this->getMocks();
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));

        $guard->url();
    }

    public function testItThrowsExceptionIfStoredStateDoestNotMatchTheRequestState()
    {
        $this->expectException(StateMismatchException::class);

        [$keycloak, $provider, $session] = $this->getMocks();
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->andReturn('456');

        $guard->handleCallback();
    }

    public function testItUpdatesTheSessionWithIdAndTokenInformation()
    {
        $token = $this->dummyAccessToken();
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $dataSet = new DataSet(['sub' => 'user-id-10'], 'encoded');
        $parsedToken = m::mock(UnencryptedToken::class);
        $user = m::mock(Authenticatable::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andReturn($token);
        $keycloak->shouldReceive('verifyTokenSignature')->with($token->getToken())->once();
        $parsedToken->shouldReceive('claims')->once()->andReturn($dataSet);
        $keycloak->shouldReceive('parseToken')->with($token->getToken())->once()->andReturn($parsedToken);
        $provider->shouldReceive('retrieveByCredentials')->with(['sub' => 'user-id-10'])->andReturn($user);
        $user->shouldReceive('getAuthIdentifier')->once()->andReturn(10);

        $guard->handleCallback();

        $session->shouldHaveReceived('put')->with(
            $guard->getName(), ['id' => 10, 'token' => $token->jsonSerialize()]
        )->once();
        $session->shouldHaveReceived('migrate')->with(true);
        $this->assertSame($user, $guard->user());
    }

    public function testItThrowsExceptionIfRetrieveByCredentialsReturnNull()
    {
        $token = $this->dummyAccessToken();
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $dataSet = new DataSet(['sub' => 'user-id-10'], 'encoded');
        $parsedToken = m::mock(UnencryptedToken::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andReturn($token);
        $keycloak->shouldReceive('verifyTokenSignature')->with($token->getToken())->once();
        $parsedToken->shouldReceive('claims')->twice()->andReturn($dataSet);
        $keycloak->shouldReceive('parseToken')->with($token->getToken())->once()->andReturn($parsedToken);
        $provider->shouldReceive('retrieveByCredentials')->with(['sub' => 'user-id-10'])->andReturn(null);

        $this->expectException(RelatedUserNotFoundException::class);
        $guard->handleCallback();

        $session->shouldNotHaveReceived('put');
        $session->shouldNotHaveReceived('migrate');
    }

    public function testItSupportsUserCreateCallbackIfUserIsNotFound()
    {
        $token = $this->dummyAccessToken();
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $dataSet = new DataSet(['sub' => 'user-id-10'], 'encoded');
        $user = m::mock(Authenticatable::class);
        $parsedToken = m::spy(UnencryptedToken::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andReturn($token);
        $keycloak->shouldReceive('verifyTokenSignature')->with($token->getToken())->once();
        $parsedToken->shouldReceive('claims')->once()->andReturn($dataSet);
        $keycloak->shouldReceive('parseToken')->with($token->getToken())->once()->andReturn($parsedToken);
        $provider->shouldReceive('retrieveByCredentials')->with(['sub' => 'user-id-10'])->andReturn(null);
        $user->shouldReceive('getAuthIdentifier')->once()->andReturn(10);

        $guard->userNotFoundHandler(function (UnencryptedToken $token) use ($user) {
            $token->payload();
            return $user;
        });
        $guard->handleCallback();

        $parsedToken->shouldHaveReceived('payload');
        $session->shouldHaveReceived('put')->with(
            $guard->getName(), ['id' => 10, 'token' => $token->jsonSerialize()]
        )->once();
        $session->shouldHaveReceived('migrate')->with(true);
        $this->assertSame($user, $guard->user());
    }

    public function testItThrowsExceptionIfCallbackReturnTypeIsNotAuthenticatable()
    {
        $token = $this->dummyAccessToken();
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $dataSet = new DataSet(['sub' => 'user-id-10'], 'encoded');
        $parsedToken = m::mock(UnencryptedToken::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andReturn($token);
        $keycloak->shouldReceive('verifyTokenSignature')->with($token->getToken())->once();
        $parsedToken->shouldReceive('claims')->once()->andReturn($dataSet);
        $keycloak->shouldReceive('parseToken')->with($token->getToken())->once()->andReturn($parsedToken);
        $provider->shouldReceive('retrieveByCredentials')->with(['sub' => 'user-id-10'])->andReturn(null);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/An instance of '.preg_quote(Authenticatable::class).' was expected/');
        $guard->userNotFoundHandler(fn() => 123);
        $guard->handleCallback();

        $session->shouldNotHaveReceived('put');
        $session->shouldNotHaveReceived('migrate');
    }

    public function testItThrowsFetchTokenFailedExceptionIfBaseProviderThrowsAnyTypeOfException()
    {
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andThrows(\Exception::class);

        $this->expectException(FetchAccessTokenFailedException::class);
        $guard->handleCallback();

        $session->shouldNotHaveReceived('put');
        $session->shouldNotHaveReceived('migrate');
    }

    public function testTokenSignatureFailedExceptionIsRethrown()
    {
        $token = $this->dummyAccessToken();
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andReturn($token);
        $keycloak->shouldReceive('verifyTokenSignature')
            ->with($token->getToken())
            ->andThrows(TokenSignatureVerificationFailed::class);

        $this->expectException(TokenSignatureVerificationFailed::class);
        $guard->handleCallback();

        $session->shouldNotHaveReceived('put');
        $session->shouldNotHaveReceived('migrate');
    }

    public function testCheckReturnsTrueIfUserIsNotNull()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $user = m::mock(Authenticatable::class);
        $request = Request::create('/', 'GET');
        $guard = m::mock(KeycloakGuard::class, ['default', $keycloak, $provider, $session, $request])->makePartial();
        $guard->shouldReceive('user')->once()->andReturn($user);

        $this->assertTrue($guard->check());
    }

    public function testCheckReturnsFalseIfUserIsNull()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $request = Request::create('/', 'GET');
        $guard = m::mock(KeycloakGuard::class, ['default', $keycloak, $provider, $session, $request])->makePartial();
        $guard->shouldReceive('user')->once()->andReturn(null);

        $this->assertFalse($guard->check());
    }

    public function testUserReturnsAuthenticatedUserIfTokenAndDetailsAreValid()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $request = Request::create('/', 'GET');
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $user = m::mock(Authenticatable::class);
        $accessToken = $this->dummyAccessToken();
        $sessionData = [
            'id' => 10,
            'token' => $accessToken->jsonSerialize()
        ];
        $session->shouldReceive('get')->with($guard->getName())->andReturn($sessionData);
        $keycloak->shouldReceive('unserializeToken')->with($sessionData['token'])->andReturn($accessToken);
        $keycloak->shouldReceive('verifyTokenSignature')->with($accessToken->getToken())->once();
        $provider->shouldReceive('retrieveById')->with(10)->andReturn($user);

        $this->assertInstanceOf(Authenticatable::class, $guard->user());
        $this->assertSame($user, $guard->user());
    }

    public function testUserReturnsRightAwayIfInstanceVariableIsNotNull()
    {
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $request = Request::create('/', 'GET');
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $user = m::mock(Authenticatable::class);
        $guard->setUser($user);

        $session->shouldNotHaveReceived('get');
        $this->assertSame($user, $guard->user());
    }

    public function testItAttemptsTokenRefreshIfTokenHasExpiredAndAuthenticatesIfFreshTokenReceived()
    {
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $request = Request::create('/', 'GET');
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $user = m::mock(Authenticatable::class);
        $dataSet = new DataSet(['sub' => 'user-id-10'], 'encoded');
        $parsedToken = m::mock(UnencryptedToken::class);
        $expiredToken = $this->dummyAccessToken(Carbon::now()->subDay()->getTimestamp());
        $sessionData = [
            'id' => 10,
            'token' => $expiredToken->jsonSerialize()
        ];
        $session->shouldReceive('get')->with($guard->getName())->andReturn($sessionData);
        $keycloak->shouldReceive('unserializeToken')->with($sessionData['token'])->andReturn($expiredToken);
        $keycloak->shouldReceive('verifyTokenSignature')->with($expiredToken->getToken());
        $newToken = $this->dummyAccessToken(Carbon::now()->addDay()->getTimestamp());
        $keycloak->shouldReceive('refreshToken')->with($expiredToken->getRefreshToken())->andReturn($newToken);
        $parsedToken->shouldReceive('claims')->once()->andReturn($dataSet);
        $keycloak->shouldReceive('parseToken')->with($newToken->getToken())->once()->andReturn($parsedToken);
        $provider->shouldReceive('retrieveByCredentials')->with(['sub' => 'user-id-10'])->andReturn($user);
        $user->shouldReceive('getAuthIdentifier')->once()->andReturn(10);
        $provider->shouldNotReceive('retrieveById');

        $session->shouldReceive('put')->with(
            $guard->getName(), ['id' => 10, 'token' => $newToken->jsonSerialize()]
        )->once();
        $session->shouldReceive('migrate')->with(true);
        $this->assertSame($user, $guard->user());
    }

    public function testItSetsUserNullIfRefreshTokenThrowsIdentityException()
    {
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $request = Request::create('/', 'GET');
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $user = m::mock(Authenticatable::class);
        $expiredToken = $this->dummyAccessToken(Carbon::now()->subDay()->getTimestamp());
        $sessionData = [
            'id' => 10,
            'token' => $expiredToken->jsonSerialize()
        ];
        $session->shouldReceive('get')->with($guard->getName())->andReturn($sessionData);
        $keycloak->shouldReceive('unserializeToken')->with($sessionData['token'])->andReturn($expiredToken);
        $keycloak->shouldReceive('verifyTokenSignature')->with($expiredToken->getToken());
        $keycloak
            ->shouldReceive('refreshToken')
            ->with($expiredToken->getRefreshToken())
            ->andThrows(IdentityProviderException::class);
        $keycloak->shouldNotReceive('parseToken');
        $provider->shouldNotReceive('retrieveByCredentials');
        $user->shouldNotReceive('getAuthIdentifier');
        $provider->shouldNotReceive('retrieveById');

        $session->shouldReceive('remove')->with($guard->getName());
        $this->assertNull($guard->user());
    }

    public function testValidateAlwaysReturnsFalseAndIsAnUnusedMethod()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $request = Request::create('/', 'GET');
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);

        $this->assertFalse($guard->validate());
    }

    public function testLogoutSetsTheUserNullAndClearsTheSession()
    {
        [$keycloak, $provider,] = $this->getMocks();
        $session = m::spy(Session::class);
        $request = Request::create('/', 'GET');
        $user = m::mock(Authenticatable::class);
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, $request);
        $keycloak->shouldReceive('getLogoutUrl')->with(['redirect_uri' => 'test'])->andReturn('https://foo.com/logout');
        $guard->setUser($user);
        $this->assertSame($user, $guard->user());

        $res = $guard->logout(['redirect_uri' => 'test']);

        $session->shouldHaveReceived('remove')->with($guard->getName());
        $this->assertNull($guard->user());
        $this->assertInstanceOf(RedirectResponse::class, $res);
    }

    public function testUserReturnsNullIfSessionIsEmpty()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));
        $session->shouldReceive('get')->once()->andReturn(null);

        $this->assertNull($guard->user());
    }

    public function testUserReturnsNullIfTokenIsNotStoredInSession()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));
        $session->shouldReceive('get')->once()->andReturn(['id' => '10']);

        $this->assertNull($guard->user());
    }

    public function testItCanReturnTheActiveTokenStoredInSession()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));
        $accessToken = $this->dummyAccessToken();
        $session->shouldReceive('get')->with($guard->getName())->andReturn(
            ['id' => 10, 'token' => $accessToken->jsonSerialize()]
        );
        $keycloak->shouldReceive('unserializeToken')->with($accessToken->jsonSerialize())->andReturn($accessToken);

        $returnedToken = $guard->token();
        $this->assertInstanceOf(AccessToken::class, $returnedToken);
        $this->assertEquals($accessToken->jsonSerialize(), $returnedToken->jsonSerialize());
    }

    public function testTokenMethodReturnsNullIfSessionIsEmpty()
    {
        [$keycloak, $provider, $session] = $this->getMocks();
        $guard = new KeycloakGuard('default', $keycloak, $provider, $session, Request::create('/', 'GET'));
        $session->shouldReceive('get')->with($guard->getName())->andReturn(null);
        $keycloak->shouldNotReceive('unserializeToken');

        $this->assertNull($guard->token());
    }

    public function testUserRetrievingCanBeOverriddenByACallback()
    {
        $token = $this->dummyAccessToken();
        $provider = m::spy(UserProvider::class);
        $session = m::spy(Session::class);
        $parsedToken = m::spy(UnencryptedToken::class);
        $user = m::mock(Authenticatable::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak = m::mock(KeycloakManager::class), $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andReturn($token);
        $keycloak->shouldReceive('verifyTokenSignature')->with($token->getToken())->once();
        $keycloak->shouldReceive('parseToken')->with($token->getToken())->once()->andReturn($parsedToken);
        $user->shouldReceive('getAuthIdentifier')->once()->andReturn(10);

        $guard->resolveUserByToken(function (UnencryptedToken $token) use ($user) {
            $token->payload();
            return $user;
        });
        $guard->handleCallback();

        $parsedToken->shouldHaveReceived('payload');
        $provider->shouldNotHaveReceived('retrieveByCredentials');
        $session->shouldHaveReceived('put')->with($guard->getName(), ['id' => 10, 'token' => $token->jsonSerialize()])->once();
        $session->shouldHaveReceived('migrate')->with(true);
        $this->assertSame($user, $guard->user());
    }

    public function testItThrowsExceptionIfTheReturnedTypeOfUserByTokenCallbackIsNotOfTypeAuthenticatable()
    {
        $token = $this->dummyAccessToken();
        $provider = m::spy(UserProvider::class);
        $session = m::spy(Session::class);
        $parsedToken = m::spy(UnencryptedToken::class);
        $user = m::mock(Authenticatable::class);
        $request = Request::create('/', 'GET', ['state' => '123', 'code' => 'code-123']);

        $guard = new KeycloakGuard('default', $keycloak = m::mock(KeycloakManager::class), $provider, $session, $request);
        $session->shouldReceive('get')->with('oauth2state')->once()->andReturn('123');
        $keycloak->shouldReceive('fetchToken')->with('code-123')->once()->andReturn($token);
        $keycloak->shouldReceive('verifyTokenSignature')->with($token->getToken())->once();
        $keycloak->shouldReceive('parseToken')->with($token->getToken())->once()->andReturn($parsedToken);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/An instance of '.preg_quote(Authenticatable::class).' was expected/');
        $guard->resolveUserByToken(fn() => 123);
        $guard->handleCallback();

        $provider->shouldNotHaveReceived('retrieveByCredentials');
        $session->shouldNotHaveReceived('put');
        $session->shouldNotHaveReceived('migrate');
        $this->assertNull($guard->user());
    }

    /**
     * @return \Mockery\MockInterface[]
     */
    protected function getMocks(): array
    {
        return [
            m::mock(KeycloakManager::class),
            m::mock(UserProvider::class),
            m::mock(Session::class)
        ];
    }

    protected function dummyAccessToken(int $expires = null): AccessToken
    {
        return new AccessToken([
            'access_token' => 'an-access-token',
            'refresh_token' => 'a-refresh-token',
            'expires' => $expires ?? Carbon::now()->addDay(1)->getTimestamp()
        ]);
    }
}
