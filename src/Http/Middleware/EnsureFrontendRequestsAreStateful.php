<?php

namespace Aloko\Keycloak\Http\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Routing\Pipeline;
use Illuminate\Support\Collection;
use Symfony\Component\HttpFoundation\Response;

class EnsureFrontendRequestsAreStateful
{
    /**
     * Handle the incoming requests.
     *
     * @param \Illuminate\Http\Request $request
     * @param callable                 $next
     *
     * @return \Illuminate\Http\Response
     */
    public function handle(Request $request, callable $next): Response
    {
        $this->configureSecureCookieSessions();

        return (new Pipeline(app()))->send($request)->through(static::fromFrontend($request) ? [
            config('keycloak.middleware.encrypt_cookies', \Illuminate\Cookie\Middleware\EncryptCookies::class),
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
            \Illuminate\Session\Middleware\StartSession::class,
            config('keycloak.middleware.verify_csrf_token', \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class),
        ] : [])->then(function ($request) use ($next) {
            return $next($request);
        });
    }

    /**
     * Configure secure cookie sessions.
     *
     * @return void
     */
    protected function configureSecureCookieSessions()
    {
        config([
            'session.http_only' => true,
            'session.same_site' => 'lax',
        ]);
    }

    /**
     * Determine if the given request is from the first-party application frontend.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return bool
     */
    public static function fromFrontend(Request $request): bool
    {
        $domain = $request->headers->get('referer') ?: $request->headers->get('origin');

        if (is_null($domain)) {
            return false;
        }

        $domain = Str::replaceFirst('https://', '', $domain);
        $domain = Str::replaceFirst('http://', '', $domain);
        $domain = Str::endsWith($domain, '/') ? $domain : "{$domain}/";

        $stateful = array_filter(config('keycloak.stateful', []));

        return Str::is(Collection::make($stateful)->map(function ($uri) {
            return trim($uri).'/*';
        })->all(), $domain);
    }
}
