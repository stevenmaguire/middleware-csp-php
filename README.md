# Content Security Policy Middleware

[![Latest Version](https://img.shields.io/github/release/stevenmaguire/middleware-csp-php.svg?style=flat-square)](https://github.com/stevenmaguire/middleware-csp-php/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/stevenmaguire/middleware-csp-php/master.svg?style=flat-square)](https://travis-ci.org/stevenmaguire/middleware-csp-php)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/stevenmaguire/middleware-csp-php.svg?style=flat-square)](https://scrutinizer-ci.com/g/stevenmaguire/middleware-csp-php/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/stevenmaguire/middleware-csp-php.svg?style=flat-square)](https://scrutinizer-ci.com/g/stevenmaguire/middleware-csp-php)
[![Total Downloads](https://img.shields.io/packagist/dt/stevenmaguire/middleware-csp.svg?style=flat-square)](https://packagist.org/packages/stevenmaguire/middleware-csp)

Provides support for enforcing Content Security Policy with headers in PSR 7 responses.

## About CSP (Content Security Policy)

> _The new Content-Security-Policy HTTP response header helps you reduce XSS risks on modern browsers by declaring what dynamic resources are allowed to load via a HTTP Header_. - via [content-security-policy.com](https://content-security-policy.com/)

### TL;DR from [Google](https://developers.google.com/web/fundamentals/security/csp/)

- Use whitelists to tell the client what's alowed and what isn't.
- Learn what directives are available.
- Learn the keywords they take.
- Inline code and eval() are considered harmful.
- Report policy violations to your server before enforcing them.

## Install

Via Composer

``` bash
$ composer require stevenmaguire/middleware-csp
```

## Usage

Frameworks and routing layer projects may implement middleware differently. This package is designed to aid in the implementation of CSP for many of those variations provided the middleware pattern expects to provide a `Psr\Http\Message\ResponseInterface` and receive an updated `Psr\Http\Message\ResponseInterface` in return.

### Generic Example

``` php
<?php namespace Stevenmaguire\Http\Middleware\Test;

use Psr\Http\Message\ResponseInterface;
use Stevenmaguire\Http\Middleware\EnforceContentSecurity;

class GenericMiddleware extends EnforceContentSecurity
{
    /**
     * Applies content security policy to given response.
     *
     * @param  ResponseInterface  $response
     * @param  array              $profiles
     *
     * @return ResponseInterface
     */
    public function handle(ResponseInterface $response, $profiles = [])
    {
        array_map(function ($profile) {
            $this->loadProfileByKey($profile);
        }, $profiles);

        return $this->addPolicyHeader($response);
    }

    /**
     * Adds profile configuration to underlying middleware.
     *
     * @param array  $profileConfig
     *
     * @return EnforceContentSecurity
     */
    public function addProfileConfiguration($profileConfig = [])
    {
        return $this->setProfiles($profileConfig);
    }

    /**
     * Encodes a given configuration into formatted directive string.
     *
     * @param  array   $config
     *
     * @return string
     */
    public function getEncodedConfiguration($config = [])
    {
        return $this->encodeConfiguration($config);
    }
}

```

In this example `$profiles` is an array of `middleware-csp-php` specific configuration that directs the package on how to decorate the response.

Here is an example of configuration for two profiles.

``` php
// within config/security.php

return [
    'content' => [
        'default' => 'global',
        'profiles' => [
            'global' => [
                'base-uri' => "'self'",
                'default-src' => "'self'",
                'font-src' => [ // e.g. only allows fonts from your server and fonts.gstatic.com
                    "'self'",
                    'fonts.gstatic.com'
                ],
                'img-src' => "'self'",
                'script-src' => "'self'",
                'style-src' => [
                    "'self'",
                    "'unsafe-inline'",
                    'fonts.googleapis.com'
                ],
            ],
            'flickr' => [
                'img-src' => [
                    'https://*.staticflickr.com',
                ],
            ],
        ],
    ],
];
```

### Framework Specific Implementations

- [Laravel](https://github.com/stevenmaguire/laravel-middleware-csp)

## Defining a CPS

You should try to keep your Content Security Policy as strict as possible. It is best to not allow inline scripts and only files from a trusted source. Only add sources that you activly use and not those that you might use in the future.

#### CSP 1.0 Spec

Directive | Description
----------|------------
`connect-src` (d) | restricts which URLs the protected resource can load using script interfaces. (e.g. send() method of an XMLHttpRequest object)
`font-src` (d) | restricts from where the protected resource can load fonts
`img-src` (d) | restricts from where the protected resource can load images
`media-src` (d) | restricts from where the protected resource can load video, audio, and associated text tracks
`object-src` (d) | restricts from where the protected resource can load plugins
`script-src` (d) | restricts which scripts the protected resource can execute. Additional restrictions against, inline scripts, and eval. Additional directives in CSP2 for hash and nonce support
`style-src` (d) | restricts which styles the user may applies to the protected resource. Additional restrictions against inline and eval.
`default-src` | Covers any directive with (d)
`frame-src` | restricts from where the protected resource can embed frames. Note, deprecated in CSP2
`report-uri` | specifies a URL to which the user agent sends reports about policy violation
`sandbox` | specifies an HTML sandbox policy that the user agent applies to the protected resource. Optional in 1.0


#### New in CSP 2.0

Directive | Description
----------|------------
`form-action` | retricts which URLs can be used as the action of HTML form elements
`frame-ancestors` | indicates whether the user agent should allow embedding the resource using a frame, iframe, object, embed or applet element, or equivalent functionality in non-HTML resources
`plugin-types` | restricts the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded
`base-uri` | restricts the URLs that can be used to specify the document base URL
`child-src` (d) | governs the creation of nested browsing contexts as well as Worker execution contexts


## Browser Support

This is a high level summary of browser support for CSP. For more detailed specifications review [Mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/CSP_policy_directives#Browser_compatibility) or [caniuse](http://caniuse.com/#search=csp)

[csp1supported]: https://img.shields.io/badge/csp%201.0-supported-green.svg
[csp1somesupport]: https://img.shields.io/badge/csp%201.0-partial-orange.svg
[csp1unsupported]: https://img.shields.io/badge/csp%201.0-unsupported-red.svg
[csp2supported]: https://img.shields.io/badge/csp%202.0-supported-green.svg
[csp2somesupport]: https://img.shields.io/badge/csp%202.0-partial-orange.svg
[csp2unsupported]: https://img.shields.io/badge/csp%202.0-unsupported-red.svg

Browser | CSP 1.0 | CSP 2.0
--------|---------|--------
Chrome | ![][csp1supported] | ![][csp2supported]
Firefox | ![][csp1supported] | ![][csp2somesupport]
Internet Explorer | ![][csp1unsupported] | ![][csp2unsupported]
Edge | ![][csp1unsupported] | ![][csp2unsupported]
Opera | ![][csp1unsupported] | ![][csp2unsupported]
Safari | ![][csp1unsupported] | ![][csp2unsupported]

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Contributing

Please see [CONTRIBUTING](https://github.com/stevenmaguire/middleware-csp-php/blob/master/CONTRIBUTING.md) for details.

## Credits

- [Steven Maguire](https://github.com/stevenmaguire)
- [All Contributors](https://github.com/stevenmaguire/middleware-csp-php/contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
