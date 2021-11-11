<?php

namespace Aloko\Keycloak;

use Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailed;
use Aloko\Keycloak\Token\DecodedToken;
use Aloko\Keycloak\Token\TokenParser;
use Illuminate\Support\Arr;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak as BaseProvider;

class KeycloakManager
{
    protected BaseProvider $provider;

    protected array $config;

    protected Configuration $jwtConfig;

    public function __construct($config, Configuration $jwtConfig)
    {
        $this->config = $config;
        $this->jwtConfig = $jwtConfig;
        $this->configureProvider();
    }

    protected function configureProvider()
    {
        $this->provider = new BaseProvider([
            'authServerUrl' => $this->config['server_url'],
            'realm' => $this->config['realm'],
            'clientId' => $this->config['client_id'],
            'clientSecret' => $this->config['client_secret'],
            'redirectUri' => url($this->config['redirect_uri']),
            'encryptionAlgorithm' => $this->config['realm_encryption_algo'],
            'encryptionKey' => $this->config['realm_public_key']
        ]);
    }

    public function getAuthorizationUrl($options = []): string
    {
        return $this->provider->getAuthorizationUrl(
            array_merge(['scope' => ['openid', 'profile', 'email']], $options)
        );
    }

    public function getState(): string
    {
        return $this->provider->getState();
    }

    /**
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function fetchToken($code): AccessToken
    {
        return $this->provider->getAccessToken('authorization_code', [
            'code' => $code
        ]);
    }

    public function parseToken(string $token): UnencryptedToken
    {
        return $this->jwtConfig->parser()->parse($token);
    }

    public function unserializeToken(array $options): AccessToken
    {
        return new AccessToken($options);
    }

    /**
     * Verify the token signature.
     *
     * @param string $token
     *
     * @return void
     * @throws \Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailed
     */
    public function verifyTokenSignature(string $token): void
    {
        try {
            $this->jwtConfig->validator()->assert(
                $this->parseToken($token),
                new SignedWith($this->jwtConfig->signer(), $this->jwtConfig->verificationKey())
            );
        } catch (RequiredConstraintsViolated | NoConstraintsGiven $e) {
            throw new TokenSignatureVerificationFailed($e->getMessage());
        }
    }

    /**
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function refreshToken($refreshToken): AccessToken
    {
        return $this->provider->getAccessToken('refresh_token', [
            'refresh_token' => $refreshToken
        ]);
    }

    public function getLogoutUrl($options = []): string
    {
        return $this->provider->getLogoutUrl(
            array_merge([
                'redirect_uri' => url(Arr::pull($options, 'redirect_uri', '/auth/logout/callback'))
            ], $options)
        );
    }

    public function provider(): BaseProvider
    {
        return $this->provider;
    }
}
