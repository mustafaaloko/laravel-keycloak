<?php

namespace Aloko\Keycloak\Token;

class TokenBag
{
    protected Token $accessToken;

    protected Token $refreshToken;

    public function __construct(Token $accessToken, Token $refreshToken)
    {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
    }

    public function accessToken(): Token
    {
        return $this->accessToken;
    }

    public function refreshToken(): Token
    {
        return $this->refreshToken;
    }

    public function isExpired(): bool
    {
        return $this->accessToken->isExpired();
    }

    public function jsonSerialize(): array
    {
        return [
            'access_token' => $this->accessToken->encoded(),
            'refresh_token' => $this->refreshToken->encoded(),
        ];
    }
}
