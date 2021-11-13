<?php

namespace Aloko\Keycloak\Tests\Token;

use Aloko\Keycloak\Tests\Utils\FakeKeys;
use Aloko\Keycloak\Token\Token;
use Carbon\Carbon;
use Carbon\CarbonInterface;
use Firebase\JWT\JWT;
use Hamcrest\Matchers;
use Lcobucci\JWT\UnencryptedToken;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class TokenTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testItReturnsTheEncodedVersionOfTheToken()
    {
        $plain = m::mock(UnencryptedToken::class);
        $token = new Token($plain);
        $plain->shouldReceive('toString')->twice()->andReturn('foo');

        $this->assertInstanceOf(Token::class, $token);
        $this->assertEquals('foo', $token->encoded());
        $this->assertEquals('foo', $token->toString());
    }

    public function testItDeterminesIfTokenIsExpired()
    {
        $plain = m::mock(UnencryptedToken::class);
        $token = new Token($plain);
        $plain->shouldReceive('isExpired')->once()->with(m::type(CarbonInterface::class))->andReturn(true);

        $this->assertTrue($token->isExpired());
    }

    public function testItTakesNowAsDefaultIfSpecificTimeIsNotPassed()
    {
        Carbon::setTestNow($now = Carbon::now());
        $plain = m::mock(UnencryptedToken::class);
        $token = new Token($plain);
        $plain->shouldReceive('isExpired')->once()->with(
            m::on(fn(CarbonInterface $time) => $time->getTimestamp() === $now->getTimestamp())
        )->andReturn(true);

        $this->assertTrue($token->isExpired());
    }

    public function testItCanSpecifyTimeByParameterToCheckTheExpiryBasedOn()
    {
        $anotherTime = Carbon::now()->subMonth();
        $plain = m::mock(UnencryptedToken::class);
        $token = new Token($plain);
        $plain->shouldReceive('isExpired')->once()->with(Matchers::identicalTo($anotherTime))->andReturn(true);

        $this->assertTrue($token->isExpired($anotherTime));
    }
}
