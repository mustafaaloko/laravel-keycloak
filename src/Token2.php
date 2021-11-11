<?php

namespace Aloko\Keycloak;

use Firebase\JWT\JWT;
use Illuminate\Support\Arr;
use League\OAuth2\Client\Token\AccessToken;

class Token2
{
    /**
     * The main access token instance.
     *
     * @var \League\OAuth2\Client\Token\AccessToken
     */
    protected $original;

    protected $publicKey;

    /**
     * The decoded version of the JWT token.
     *
     * @var stdClass
     */
    protected $decoded;

    public function __construct($accessToken, $publicKey)
    {
        $accessToken = is_array($accessToken) ? new AccessToken($accessToken) : $accessToken;

        $this->original = $accessToken;
        $this->publicKey = $publicKey;

        if (!$this->isExpired()) {
            $this->decoded = $this->decode();
        }
    }

    public static function parse($accessToken, $publicKey): Token2
    {
        return new static($accessToken, $publicKey);
    }

    protected function decode()
    {
        JWT::$leeway = 5;

        $decoded = JWT::decode(
            $this->original->getToken(),
            $this->publicKey,
            ['RS256']
        );

        return json_decode(json_encode($decoded), true);
    }

    public function decoded()
    {
        return $this->decoded;
    }

    public function getRefreshToken()
    {
        return $this->original->getRefreshToken();
    }

    public function sub()
    {
        if ($this->decoded) {
            return $this->decoded['sub'];
        }
    }

    public function userInfo()
    {
        if ($this->decoded) {
            return Arr::only($this->decoded, [
                'sub', 'name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified'
            ]);
        }
    }

    public function isExpired(): bool
    {
        return $this->original->hasExpired();
    }

    public function jsonSerialize(): array
    {
        return $this->original->jsonSerialize();
    }
}
