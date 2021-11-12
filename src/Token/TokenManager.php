<?php

namespace Aloko\Keycloak;

use Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailed;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Client\Token\AccessToken;

class TokenManager
{
    protected Configuration $jwtConfig;

    /**
     * Verify the token signature.
     *
     * @param string $token
     *
     * @return void
     * @throws \Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailed
     */
    public function verifyTokenSignature(string $token): void
    {
        try {
            $this->jwtConfig->validator()->assert(
                $this->parseToken($token),
                new SignedWith($this->jwtConfig->signer(), $this->jwtConfig->verificationKey())
            );
        } catch (RequiredConstraintsViolated | NoConstraintsGiven $e) {
            throw new TokenSignatureVerificationFailed($e->getMessage());
        }
    }

    public function unserializeToken(array $options): AccessToken
    {
        return new AccessToken($options);
    }

    public function parseToken(string $token): UnencryptedToken
    {
        return $this->jwtConfig->parser()->parse($token);
    }
}
