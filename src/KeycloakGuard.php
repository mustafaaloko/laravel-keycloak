<?php

namespace Aloko\Keycloak;

use Aloko\Keycloak\Token\Token;
use Aloko\Keycloak\Token\TokenBag;
use Exception;
use RuntimeException;
use BadMethodCallException;
use Illuminate\Support\Arr;
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Lcobucci\JWT\UnencryptedToken;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\RedirectResponse;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Auth\UserProvider;
use League\OAuth2\Client\Token\AccessToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Aloko\Keycloak\Exceptions\StateMismatchException;
use Aloko\Keycloak\Exceptions\RelatedUserNotFoundException;
use Aloko\Keycloak\Exceptions\FetchAccessTokenFailedException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

class KeycloakGuard implements Guard
{
    use GuardHelpers;

    /**
     * The name of the guard. Typically, "web".
     *
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected string $name;

    /**
     * The base Keycloak instance.
     *
     * @var \Aloko\Keycloak\KeycloakManager
     */
    protected KeycloakManager $keycloak;

    /**
     * The session instance used by guard.
     *
     * @var \Illuminate\Contracts\Session\Session
     */
    protected Session $session;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected Request $request;

    /**
     * Callback to create users if not found in the system.
     *
     * @var callable|null
     */
    protected $userNotFoundCallback = null;

    /**
     * User resolver by token.
     *
     * @var callable|null
     */
    protected $userResolverByToken = null;

    /**
     * The calculated authorization URL.
     *
     * @var string|null
     */
    protected ?string $authUrl = null;

    /**
     * Creates a new Keycloak Guard instance.
     *
     * @param                                         $name
     * @param \Aloko\Keycloak\KeycloakManager         $keycloak
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Illuminate\Contracts\Session\Session   $session
     * @param \Illuminate\Http\Request                $request
     *
     * @return void
     */
    public function __construct($name, KeycloakManager $keycloak, UserProvider $provider, Session $session, Request $request)
    {
        $this->name = $name;
        $this->keycloak = $keycloak;
        $this->provider = $provider;
        $this->session = $session;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     * @throws \Aloko\Keycloak\Exceptions\RelatedUserNotFoundException
     * @throws \Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailedException
     */
    public function user(): ?Authenticatable
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        if ($session = $this->retrieveSession()) {
            $this->keycloak->verifyTokenSignature(
                $tokenBag = $this->keycloak->unserializeToken($session['token'])
            );

            // If the token has not expired, we will just attempt to retrieve the current
            // user instance using the ID stored in the session and return it back.
            if (! $tokenBag->accessToken()->isExpired()) {
                return $this->user = $this->provider->retrieveById($session['id']);
            }

            // Otherwise, we attempt a token refresh using the current token and then attempt
            // a new login with the new token received, if all good, we will store the new
            // token's data to replace old token's data to be used in future attempts.
            return $this->attemptLoginWithNewToken(
                $this->attemptTokenRefresh($tokenBag)
            );
        }

        return $this->user;
    }

    /**
     * Attempts a login flow by redirecting the user to keycloak.
     *
     * @param array $options
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function attempt(array $options = []): RedirectResponse
    {
        return new RedirectResponse(
            $this->prepare($options)->url()
        );
    }

    /**
     * Prepare the guard for a login attempt.
     *
     * @param array $options
     *
     * @return $this
     */
    public function prepare(array $options = []): self
    {
        $this->authUrl = $this->keycloak->getAuthorizationUrl(
            array_merge(['scope' => ['openid', 'profile', 'email']], $options) // TODO: Bring this to Provider class
        );

        $this->session->put('oauth2state', $this->keycloak->getState());
        $this->session->save();

        return $this;
    }

    /**
     * Returns the calculated authorization URL to keycloak.
     *
     * @return string
     */
    public function url(): string
    {
        if (is_null($this->authUrl)) {
            throw new BadMethodCallException("Method cannot be called directly, call prepare() before this method");
        }

        return $this->authUrl;
    }

    /**
     * Handles the callback from keycloak.
     *
     * @param \Illuminate\Http\Request|null $request
     *
     * @return void
     * @throws \Aloko\Keycloak\Exceptions\FetchAccessTokenFailedException
     * @throws \Aloko\Keycloak\Exceptions\RelatedUserNotFoundException
     * @throws \Aloko\Keycloak\Exceptions\StateMismatchException
     * @throws \Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailedException
     */
    public function handleCallback(Request $request = null): void
    {
        $request = $request ?? $this->request;

        if ($request->get('state') !== $this->session->get('oauth2state')) {
            throw new StateMismatchException('OIDC state mismatch.');
        }

        $this->keycloak->verifyTokenSignature(
            $tokenBag = $this->exchangeCodeForToken($request->get('code'))
        );

        $user = $this->resolveUser(
            $this->keycloak->parseToken($tokenBag)
        );

        $this->login($user, $tokenBag);
    }

    /**
     * Attempts a refresh token call.
     *
     * @param \Aloko\Keycloak\Token\TokenBag $token
     *
     * @return \League\OAuth2\Client\Token\AccessToken|null
     */
    protected function attemptTokenRefresh(TokenBag $token): ?TokenBag
    {
        try {
            return $this->keycloak->refreshToken($token);
        } catch (FetchAccessTokenFailedException $e) {
            return null; // TODO: To be handled in a better way
        }
    }

    /**
     * Registers a user creation callback.
     *
     * @param callable $cb
     *
     * @return void
     */
    public function userNotFoundHandler(callable $cb): void
    {
        $this->userNotFoundCallback = $cb;
    }

    /**
     * Register a callback to return a user instance by provided token.
     *
     * @param callable $cb
     *
     * @return void
     */
    public function resolveUserByToken(callable $cb): void
    {
        $this->userResolverByToken = $cb;
    }

    /**
     * Logins a user into the application.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param \Aloko\Keycloak\Token\TokenBag             $token
     *
     * @return void
     */
    public function login(Authenticatable $user, TokenBag $token)
    {
        $this->updateSession($user, $token);

        $this->setUser($user);
    }

    /**
     * Update the session with the given ID.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param \Aloko\Keycloak\Token\TokenBag             $token
     *
     * @return void
     */
    protected function updateSession(Authenticatable $user, TokenBag $token): void
    {
        $data = [
            'id' => $user->getAuthIdentifier(),
            'token' => $token->jsonSerialize()
        ];

        $this->session->put($this->getName(), $data);
        $this->session->migrate(true);
    }

    /**
     * Get a unique identifier for the auth session value.
     *
     * @return string
     */
    public function getName(): string
    {
        return 'login_kc_'.$this->name.'_'.sha1(static::class);
    }

    /**
     * Retrieves the current stored token.
     *
     * @return \Aloko\Keycloak\Token\TokenBag|null
     */
    public function token(): ?TokenBag
    {
        if ($session = $this->retrieveSession()) {
            return $this->keycloak->unserializeToken($session['token']);
        }

        return null;
    }

    /**
     * Resolve a user from the database using the passed token.
     *
     * @param \Aloko\Keycloak\Token\Token $token
     * @param bool                        $upsert
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     * @throws \Aloko\Keycloak\Exceptions\RelatedUserNotFoundException
     */
    protected function resolveUser(Token $token, bool $upsert = true): ?Authenticatable
    {
        $user = $this->retrieveUserByToken($token);

        if (! $upsert) {
            return $user;
        }

        if (is_null($user)) {
            $user = $this->resolveUserFromCallback($token);
        }

        if (is_null($user)) {
            throw new RelatedUserNotFoundException(
                "User with 'sub' claim #{$token->claims()->get('sub')} not found in local database"
            );
        }

        return $user;
    }

    /**
     * Attempt exchanging code for an access token.
     *
     * @param string $code
     *
     * @return \Aloko\Keycloak\Token\TokenBag
     * @throws \Aloko\Keycloak\Exceptions\FetchAccessTokenFailedException
     */
    protected function exchangeCodeForToken(string $code): TokenBag
    {
        try {
            return $this->keycloak->fetchToken($code);
        } catch (Exception $ex) {
            throw new FetchAccessTokenFailedException("Fetching Token failed: {$ex->getMessage()}");
        }
    }

    /**
     * Performs the user logout process.
     *
     * @param array $options
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function logout(array $options = []): RedirectResponse
    {
        $this->session->remove($this->getName());
        $this->user = null;

        return new RedirectResponse(
            $this->keycloak->getLogoutUrl($options)
        );
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * Resolve the user using the user provided callback.
     *
     * @param \Aloko\Keycloak\Token\Token $token
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function resolveUserFromCallback(Token $token): ?Authenticatable
    {
        if (is_null($this->userNotFoundCallback)) {
            return null;
        }

        $user = call_user_func($this->userNotFoundCallback, $token);

        if (!$user instanceof Authenticatable) {
            throw new RuntimeException('An instance of '.Authenticatable::class.' was expected from callback, '.gettype($user). ' given.');
        }

        return $user;
    }

    /**
     * Retrieve the session content.
     *
     * @return array|null
     */
    protected function retrieveSession(): ?array
    {
        $session = $this->session->get($this->getName());

        if (is_array($session) && Arr::has($session, ['id', 'token'])) {
            return $session;
        }

        return null;
    }

    /**
     * Attempt a fresh login to replace old token data with new one.
     *
     * @param \Aloko\Keycloak\Token\TokenBag|null $tokenBag
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     * @throws \Aloko\Keycloak\Exceptions\RelatedUserNotFoundException
     */
    protected function attemptLoginWithNewToken(?TokenBag $tokenBag): ?Authenticatable
    {
        if (is_null($tokenBag)) {
            $this->session->remove($this->getName());
            return $this->user = null;
        }

        $user = $this->resolveUser($tokenBag->accessToken(), false);

        return $this->user = tap($user, function ($user) use ($tokenBag) {
            $this->login($user, $tokenBag);
        });
    }

    /**
     * Retrieve the authenticatable instance by token.
     *
     * @param \Aloko\Keycloak\Token\Token $token
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    protected function retrieveUserByToken(Token $token): ?Authenticatable
    {
        if (!is_null($this->userResolverByToken)) {
            $user = call_user_func($this->userResolverByToken, $token);

            if (!$user instanceof Authenticatable) {
                throw new RuntimeException('An instance of '.Authenticatable::class.' was expected from callback, '.gettype($user). ' given.');
            }

            return $user;
        }

        return $this->provider->retrieveByCredentials([
            'sub' => $token->claims()->get('sub')
        ]);
    }
}
