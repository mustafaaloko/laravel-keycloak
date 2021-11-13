<?php

namespace Aloko\Keycloak\Token;

use Carbon\Carbon;
use DateTimeInterface;
use Lcobucci\JWT\UnencryptedToken;

class Token
{
    protected UnencryptedToken $parsed;

    public function __construct(UnencryptedToken $parsed)
    {
        $this->parsed = $parsed;
    }

    public function isExpired(DateTimeInterface $time = null): bool
    {
        return $this->parsed->isExpired($time ?? Carbon::now());
    }

    public function encoded(): string
    {
        return $this->parsed->toString();
    }

    public function toString(): string
    {
        return $this->encoded();
    }
}
