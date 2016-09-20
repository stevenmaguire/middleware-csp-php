# Content Security Policy Middleware

[![Latest Version](https://img.shields.io/github/release/stevenmaguire/middleware-csp-php.svg?style=flat-square)](https://github.com/stevenmaguire/middleware-csp-php/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/stevenmaguire/middleware-csp-php/master.svg?style=flat-square)](https://travis-ci.org/stevenmaguire/middleware-csp-php)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/stevenmaguire/middleware-csp-php.svg?style=flat-square)](https://scrutinizer-ci.com/g/stevenmaguire/middleware-csp-php/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/stevenmaguire/middleware-csp-php.svg?style=flat-square)](https://scrutinizer-ci.com/g/stevenmaguire/middleware-csp-php)
[![Total Downloads](https://img.shields.io/packagist/dt/stevenmaguire/middleware-csp.svg?style=flat-square)](https://packagist.org/packages/stevenmaguire/middleware-csp)

Provides support for enforcing Content Security Policy with headers in PSR 7 responses.

## About CSP (Content Security Policy)

// - a little bit about the risk that csp protects you against    
// - what a CSP is

## Install

Via Composer

``` bash
$ composer require stevenmaguire/middleware-csp
```

## Usage

``` php
// Obviously this should be added
```

## Defining a CPS

You should try to keep your Content Security Policy as strict as possible. It is best to not allow inline scripts and only files from a trusted source. Only add sources that you activly use and not those that you might use in the future.

#### CSP 1.0 Spec
```
connect-src (d) - restricts which URLs the protected resource can load using script interfaces. (e.g. send() method of an XMLHttpRequest object)
font-src (d) - restricts from where the protected resource can load fonts
img-src (d) - restricts from where the protected resource can load images
media-src (d) - restricts from where the protected resource can load video, audio, and associated text tracks
object-src (d) - restricts from where the protected resource can load plugins
script-src (d) - restricts which scripts the protected resource can execute. Additional restrictions against, inline scripts, and eval. Additional directives in CSP2 for hash and nonce support
style-src (d) - restricts which styles the user may applies to the protected resource. Additional restrictions against inline and eval.
default-src - Covers any directive with (d)
frame-src - restricts from where the protected resource can embed frames. Note, deprecated in CSP2
report-uri - specifies a URL to which the user agent sends reports about policy violation
sandbox - specifies an HTML sandbox policy that the user agent applies to the protected resource. Optional in 1.0
```

#### New in CSP2
```
form-action - retricts which URLs can be used as the action of HTML form elements
frame-ancestors - indicates whether the user agent should allow embedding the resource using a frame, iframe, object, embed or applet element, or equivalent functionality in non-HTML resources
plugin-types - restricts the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded
base-uri - restricts the URLs that can be used to specify the document base URL
child-src (d) - governs the creation of nested browsing contexts as well as Worker execution contexts
```

#### Example

```
// within config/security.php

return [
    'content' => [
        'default' => 'global',
        'profiles' => [
            'global' => [
                'base-uri' => "'self'", // maybe add comments what the lines mean
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

## Support

Maybe add a small table for csp 1 & csp 2 plus a link to http://caniuse.com/#search=csp

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
