<?php

namespace Aloko\Keycloak;

use Aloko\Keycloak\Token\DecodedToken;
use Aloko\Keycloak\Token\TokenParser;
use Illuminate\Support\Arr;
use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak as BaseProvider;

class KeycloakProvider extends BaseProvider
{
    protected array $config;

    public static function createFromConfig(array $config): KeycloakProvider
    {
        return new static([
            'authServerUrl' => $config['server_url'],
            'realm' => $config['realm'],
            'clientId' => $config['client_id'],
            'clientSecret' => $config['client_secret'],
            'redirectUri' => $config['redirect_uri'],
            'encryptionAlgorithm' => $config['realm_encryption_algo'],
            'encryptionKey' => $config['realm_public_key']
        ]);
    }

    /**
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function fetchToken($code): AccessToken
    {
        return $this->getAccessToken('authorization_code', [
            'code' => $code
        ]);
    }

    /**
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function refreshToken($refreshToken): AccessToken
    {
        return $this->getAccessToken('refresh_token', [
            'refresh_token' => $refreshToken
        ]);
    }

    public function getLogoutUrl(array $options = []): string
    {
        return parent::getLogoutUrl(
            array_merge([
                'redirect_uri' => Arr::pull($options, 'redirect_uri', '/auth/logout/callback')
            ], $options)
        );
    }
}
