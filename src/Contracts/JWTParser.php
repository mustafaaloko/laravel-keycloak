<?php

namespace Aloko\Keycloak\Contracts;

use Aloko\Keycloak\Token\Token;
use Lcobucci\JWT\Configuration;

interface JWTParser
{
    public function parse(string $jwt): Token;

    public function setConfiguration(Configuration $jwtConfig);
}
