# ***WORK IN PROGRESS***
Although fully functional, this package is still not recommended for production use yet. Last few steps are remaining to be completed soon. Thanks!

# Laravel Keycloak

This package is a Laravel client driver for Keycloak authentication.

## Installation

You can install the package via composer:

```bash
composer require aloko/keycloak
```
To publish the config file, you need to run the below command.
```bash
php artisan vendor:publish --tag=config --provider="Aloko\Keycloak\KeycloakServiceProvider"
```
This will create a config file named `keycloak.php` where you can alter various configurations as per your needs.

## Configuration
The second step after installation should be configuring this Keycloak client to properly find and connect with Keycloak server.

```php
<?php

return [
    'server_url' => env('KEYCLOAK_SERVER_URL', 'http://localhost:8080'),
   
    'realm' => env('KEYCLOAK_REALM'),

    'client_id' => env('KEYCLOAK_CLIENT_ID'), // The client ID you have created for this client

    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'), // The client secret you have created for this client

    'redirect_uri' => env('KEYCLOAK_REDIRECT_URI', '/auth/callback'), // The redirect uri to which the authorization code will be sent

    'realm_encryption_algo' => env('KEYCLOAK_REALM_ENCRYPTION_ALGO', 'RS256'), // The encryption keys algorithm
    
    'realm_public_key' => env('KEYCLOAL_REALM_PUBLIC_KEY'), // The public key related to this realm

    'stateful' => explode(',', env('KEYCLOAK_STATEFUL_DOMAINS', sprintf(
        '%s%s',
        'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',
        env('APP_URL') ? ','.parse_url(env('APP_URL'), PHP_URL_HOST) : ''
    ))), // Only needed for SPAs (Single-Page Applications). Check the docs below for more info
];
```

The next thing you should do is to set `keycloak` as the default authentication driver for your application. You can change this in your app's `config/auth.php`.
```php
'guards' => [
    'web' => [
        'driver' => 'keycloak', // THIS LINE
        'provider' => 'users',
    ],

    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
]
```

### Users Table Migration
This package expects a field named `sub` in your users table which contains the unique ID of the users from the Keycloak server end. This is the field that relates a user record from keycloaks database with our local database's `users` table. You can create that field in your migrations as below.

```php
Schema::table('users', function (Blueprint $table) {
    $table->string('sub', 191)->nullable()->after('id');
});
```
## Usage
Once the configuration is updated with your Keycloak server and local application details. You can start using it in the app. In addition to the methods provided in [`Illuminate\Contracts\Auth\Guard`](https://laravel.com/api/8.x/Illuminate/Contracts/Auth/Guard.html) interface (`Auth::check()`, `Auth::user()` `Auth::guest()`, `Auth::id()`), this package also provides few additional convenience methods suitable to Keycloak flows. These are `Auth::attempt(array $config)`, `Auth::handleCallback()`, `Auth::userCreateResolver(callable $callback)` and `Auth::logout()`.

### Sending to Keycloak for Authentication
You can use `Auth::attempt()` to redirect users to your Keycloak server for the actual authentication process and to obtain an **authorization code** in case of a successful login. You can put this in one of your controller methods to initiate the process.

```php
public function login(Request $request)
{
    if (Auth::guest()) {
        Auth::attempt();
    }
}
```

This method also accepts a `$config` array where you can override configs like `scope` and `redirect_uri`. The default value for `redirect_uri` is used based on the one set in your main configuration file.

### Handling Callback
After a successful authentication, the user will be redirected back to your app to the congfigured `redirect_uri` path explained above. Here you can catch this redirect in your routes file and pass the process to this package's `Auth::handleCallback()` method which will do all the magic (exchanging the authorization code with access token, id token and referesh token, and validating and persisting the token data in the session) behind the scenes and authenticate the user for you.

```php
Route::get('/auth/callback', function () {
    try {
        Auth::handleCallback();

        return redirect()->route('/dashboard')
    } catch (Exception $e) {
        // Handle the failed authentication the way you want.     
    }
})
```

The `Auth::handleCallback()` method throws 3 type of more specific exceptions based on the failure. 

1. `FetchAccessTokenFailedException`
2. `StateMismatchException`
3. `RelatedUserNotFoundException`

### Handling New Users
By default, this package will only successfully authenticate users if a related record (checked by `sub` field) exists in app's local database, if it doesn't exist, it will throw `RelatedUserNotFoundException` on `Auth::handleCallback()` call.

To allow you to handle this scenario, you can register a callback and return a new instance of user in case the user is not found in the local database. Laravel Keycloak will call this callback whenever a related user is not found in your local database. You can register this callback in your app service provider by calling `Auth::userCreateResolver($callback)`. An instance of `Aloko\Keycloak\Token` retrieved from Keycloak side is also passed to the callback.

You can fetch the Keycloak user's basic profile details by calling `$token->userInfo()` which will return an array of users details (`['sub', 'name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified']`).

```php
class AppServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        Auth::userCreateResolver(function (Token $token) {
            $data = $token->userInfo();

            return User::firstOrCreate(
                ['sub' => $data['sub']],
                ['email' => $data['email'], 'name' => $data['name']]
            );
        });
    }
}
```

### Users Logout
You can logout users by simply calling the `Auth::logout(array $config)` which also accepts a config array using which you can override defaults such as `redirect_uri`. The `redirect_uri` for logout defaults to `/auth/logout/callback` which Keycloak will redirect to once it kills the session from its own side. You can handle the callback like below and do some additional cleanups if required.

```php
Route::get('auth/logout/callback', function() {
    return redirect()->route('login');
});
```

## Using with SPAs (Single-Page Applications)
To also support SPAs, this package is using the same technique as [Laravel Sanctum](https://laravel.com/docs/8.x/sanctum) which allows using Laravel's built-in cookie based session authentication services for protecting your app as well as your SPA. Typically, this package utilizes Laravel's web authentication guard to accomplish this. This provides the benefits of CSRF protection, session authentication, as well as protects against leakage of the authentication credentials (Keycloak access tokens, id tokens, etc.) via XSS.

So if your frontend is a SPA (meaning you are using the `/api` routes of your Laravel backend) and is served on the same top-level domain (subdomains can be different), you need to do two additional configs. 

**1)** Set your SPA's domain under `stateful` configuration option, it must include the port number, if any (e.g. domain.com, domain.com:9090, localhost:8080)

**2)** Use the `EnsureFrontendRequestsAreStateful` middleware in your `Kernel.php`. This middleware will ensure to configure your API request in a way to successfully authenticate with your currently logged-in Keycloak session.

```php
protected $middlewareGroups = [
    'api' => [
        \Aloko\Keycloak\Http\Middleware\EnsureFrontendRequestsAreStateful::class,
        'throttle:120,1',
        'bindings'
    ],
];
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Security

If you discover any security related issues, please email mustafa.aloko@gmail.com instead of using the issue tracker.

## Credits

-   [Mustafa Ehsan Alokozay](https://github.com/aloko)
-   [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
