<?php

namespace Aloko\Keycloak\Token;

class TokenBag extends \Aloko\Keycloak\Token\Token
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

    public function jsonSerialize(): array
    {
        return [
            'access_token' => $this->accessToken->encoded(),
            'refresh_token' => $this->refreshToken->encoded(),
        ];
    }
}
