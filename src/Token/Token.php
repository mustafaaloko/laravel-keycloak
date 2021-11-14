<?php

namespace Aloko\Keycloak\Token;

use Carbon\Carbon;
use DateTimeInterface;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;

class Token
{
    protected UnencryptedToken $parsed;

    public function __construct(UnencryptedToken $parsed)
    {
        $this->parsed = $parsed;
    }

    public function subject()
    {
        return $this->parsed->claims()->get(RegisteredClaims::SUBJECT);
    }

    public function sub()
    {
        return $this->subject();
    }

    public function claims(): DataSet
    {
        return $this->parsed->claims();
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
