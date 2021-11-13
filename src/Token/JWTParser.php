<?php

namespace Aloko\Keycloak\Token;

use Lcobucci\JWT\Configuration;
use Aloko\Keycloak\Contracts\JWTParser as JWTParserContract;
use RuntimeException;

class JWTParser implements JWTParserContract
{
    protected ?Configuration $configuration;

    public function __construct(Configuration $configuration = null)
    {
        $this->configuration = $configuration;
    }

    public function parse(string $jwt): Token
    {
        $this->ensureConfigExists();

        return new Token(
            $this->configuration->parser()->parse($jwt)
        );
    }

    public function setConfiguration(Configuration $jwtConfig)
    {
        $this->configuration = $jwtConfig;
    }

    protected function ensureConfigExists(): JWTParser
    {
        if (is_null($this->configuration)) {
            throw new RuntimeException('The configuration property for the parser cannot be empty.');
        }

        return $this;
    }
}
