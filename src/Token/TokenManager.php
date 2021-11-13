<?php

namespace Aloko\Keycloak\Token;

use Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailedException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Client\Token\AccessToken;
use Aloko\Keycloak\Contracts\JWTParser as JWTParserContract;

class TokenManager
{
    protected Configuration $jwtConfig;

    public function __construct(Configuration $jwtConfig)
    {
        $this->jwtConfig = $jwtConfig;
    }

    /**
     * Verify the token signature.
     *
     * @param string $token
     *
     * @return void
     * @throws \Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailedException
     */
    public function verifySignature(string $token): void
    {
        try {
            $this->jwtConfig->validator()->assert(
                $this->decryptToken($token),
                new SignedWith($this->jwtConfig->signer(), $this->jwtConfig->verificationKey())
            );
        } catch (RequiredConstraintsViolated | NoConstraintsGiven $e) {
            throw new TokenSignatureVerificationFailedException($e->getMessage());
        }
    }

    public function unserializeToken(array $options): TokenBag
    {
        return $this->createBag(new AccessToken($options));
    }

    public function parse(string $jwt): Token
    {
        return new Token($this->decryptToken($jwt));
    }

    public function createBag(AccessToken $token): TokenBag
    {
        return new TokenBag(
            $this->parse($token->getToken()),
            $this->parse($token->getRefreshToken())
        );
    }

    protected function decryptToken(string $jwt): UnencryptedToken
    {
        return $this->jwtConfig->parser()->parse($jwt);
    }
}
