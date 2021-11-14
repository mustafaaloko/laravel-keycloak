<?php

/*
 * You can place your custom package configuration in here.
 */
return [
    'server_url' => env('KEYCLOAK_SERVER_URL', 'http://localhost:8080'),
   
    'realm' => env('KEYCLOAK_REALM'),

    'client_id' => env('KEYCLOAK_CLIENT_ID'),

    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),

    'redirect_uri' => env('KEYCLOAK_REDIRECT_URI', '/auth/callback'),

    'realm_encryption_algo' => env('KEYCLOAK_REALM_ENCRYPTION_ALGO', 'RS256'),
    
    'realm_public_key' => env('KEYCLOAL_REALM_PUBLIC_KEY', 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlCGs21LuL26MwYS/QHyEHPrJXJfgRGHvSvtrbJoPqQaDT0/ZhHVcXxePt1hCADvyldBaV+l5lMrK+rnCoycFkLRfBOdz+xlR2pftQN+fGL4bYtxHwEDWIi+tJSJ6X0Z1FTCs0jl/5iZyT21RKBTQsYdfFuc+BmU7li+Y1hfoRo0GFuZqDlghPkgt104sflpEe/HM6M6iqOnNoBQDwETF5nosnM5wXCcQWdTpGSqoPUttQ94pg105UiOAbSVJ0i0avEfekXSh3rNvVwaXZqJdt7LzXfnH8rs3Z8EZlqwpWT/bWFwUrgIL96aM0dyhrE2Ofu6sjmuFiGnbsYW1EP/7awIDAQAB'),

    'stateful' => explode(',', env('KEYCLOAK_STATEFUL_DOMAINS', sprintf(
        '%s%s',
        'localhost,localhost:3000,localhost:8080,127.0.0.1,127.0.0.1:8000,::1',
        env('APP_URL') ? ','.parse_url(env('APP_URL'), PHP_URL_HOST) : ''
    )))
];