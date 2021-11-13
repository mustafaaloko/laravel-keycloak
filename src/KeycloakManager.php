<?php

namespace Aloko\Keycloak;

use Aloko\Keycloak\Exceptions\FetchAccessTokenFailedException;
use Aloko\Keycloak\Token\JWTParser;
use Aloko\Keycloak\Token\Token;
use Aloko\Keycloak\Token\TokenBag;
use Aloko\Keycloak\Token\TokenManager;
use Illuminate\Support\Arr;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class KeycloakManager
{
    protected Keycloak $provider;

    private TokenManager $tokenManager;

    public function __construct(array $config, TokenManager $tokenManager)
    {
        $this->provider = new Keycloak([
            'authServerUrl' => $config['server_url'],
            'realm' => $config['realm'],
            'clientId' => $config['client_id'],
            'clientSecret' => $config['client_secret'],
            'redirectUri' => $config['redirect_uri'],
            'encryptionAlgorithm' => $config['realm_encryption_algo'],
            'encryptionKey' => $config['realm_public_key']
        ]);

        $this->tokenManager = $tokenManager;
    }

    /**
     * @throws \Aloko\Keycloak\Exceptions\FetchAccessTokenFailedException
     */
    public function fetchToken($code): TokenBag
    {
        try {
            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $code
            ]);

            return $this->tokenManager->createBag($token);
        } catch (IdentityProviderException $e) {
            throw new FetchAccessTokenFailedException('Fetching access token failed: ' . $e->getMessage());
        }
    }

    /**
     * @throws \Aloko\Keycloak\Exceptions\FetchAccessTokenFailedException
     */
    public function refreshToken(TokenBag $oldTokenBag): TokenBag
    {
        try {
            $newToken = $this->provider->getAccessToken('refresh_token', [
                'refresh_token' => $oldTokenBag->refreshToken()->encoded()
            ]);

            return $this->tokenManager->createBag($newToken);
        } catch (IdentityProviderException $e) {
            throw new FetchAccessTokenFailedException('Fetching refresh token failed: ' . $e->getMessage());
        }
    }

    public function getLogoutUrl(array $options = []): string
    {
        return $this->provider->getLogoutUrl(
            array_merge([
                'redirect_uri' => Arr::pull($options, 'redirect_uri', '/auth/logout/callback')
            ], $options)
        );
    }

    /**
     * @throws \Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailedException
     */
    public function verifyTokenSignature(Token $token)
    {
        $this->tokenManager->verifySignature($token->encoded());
    }

    public function unserializeToken(array $token): TokenBag
    {
        return $this->tokenManager->unserializeToken($token);
    }
}
