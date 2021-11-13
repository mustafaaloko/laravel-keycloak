<?php

namespace Aloko\Keycloak\Tests\Token;

use Aloko\Keycloak\Exceptions\TokenSignatureVerificationFailedException;
use Aloko\Keycloak\Token\Token;
use Aloko\Keycloak\Token\TokenManager;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validator;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class TokenManagerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testItCanParseAToken()
    {
        $config = Configuration::forUnsecuredSigner();
        $parser = m::mock(Parser::class);
        $config->setParser($parser);
        $unencryptedToken = m::mock(UnencryptedToken::class);
        $unencryptedToken->shouldReceive('toString')->andReturn('foo');
        $parser->shouldReceive('parse')->with('foo')->andReturn($unencryptedToken);

        $manager = new TokenManager($config);
        $returnedToken = $manager->parse('foo');

        $this->assertInstanceOf(Token::class, $returnedToken);
        $this->assertSame('foo', $returnedToken->encoded());
    }

    public function testItThrowsValidationExceptionIfVerificationFailsAtLowLevel()
    {
        $config = Configuration::forUnsecuredSigner();
        $validator = m::mock(Validator::class);
        $parser = m::mock(Parser::class);
        $config->setParser($parser);
        $config->setValidator($validator);
        $unencryptedToken = m::mock(UnencryptedToken::class);
        $parser->shouldReceive('parse')->with('foo')->andReturn($unencryptedToken);
        $validator->shouldReceive('assert')
            ->with($unencryptedToken, m::type(Constraint\SignedWith::class))
            ->andThrows(RequiredConstraintsViolated::class);

        $this->expectException(TokenSignatureVerificationFailedException::class);
        $manager = new TokenManager($config);
        $manager->verifySignature('foo');
    }

    public function testItThrowsValidationExceptionIfNoConstraintValidationExceptionIsThrownFromLowLevel()
    {
        $config = Configuration::forUnsecuredSigner();
        $validator = m::mock(Validator::class);
        $parser = m::mock(Parser::class);
        $config->setParser($parser);
        $config->setValidator($validator);
        $unencryptedToken = m::mock(UnencryptedToken::class);
        $parser->shouldReceive('parse')->with('foo')->andReturn($unencryptedToken);
        $validator->shouldReceive('assert')
            ->with($unencryptedToken, m::type(Constraint\SignedWith::class))
            ->andThrows(NoConstraintsGiven::class);

        $this->expectException(TokenSignatureVerificationFailedException::class);
        $manager = new TokenManager($config);
        $manager->verifySignature('foo');
    }
}
