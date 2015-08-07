<?php namespace Stevenmaguire\Http\Middleware\Test;

use Mockery as m;
use Stevenmaguire\Http\Middleware\Exceptions\CspValidationException;

class EnforceContentSecurityTest extends \PHPUnit_Framework_TestCase
{
    protected $header = 'Content-Security-Policy';

    public function setUp()
    {
        parent::setUp();
        $this->middleware = new GenericMiddleware;
    }

    protected function getResponseMock()
    {
        return m::mock('Psr\Http\Message\ResponseInterface');
    }

    protected function getAvailableDirectives()
    {
        return GenericMiddleware::getAvailableDirectives();
    }

    protected function getAvailableDomains()
    {
        return [
            'http://google.com','http://domain.com','http://foo.bar','http://pewpew.co'
        ];
    }

    protected function getDomains()
    {
        $domains = [];
        $availableDomains = $this->getAvailableDomains();
        $keys = array_rand($availableDomains, rand(1, count($availableDomains)));

        if (!is_array($keys)) {
            $keys = [$keys];
        }

        array_map(function ($key) use (&$domains, $availableDomains) {
            $domains[] = $availableDomains[$key];
        }, $keys);

        return $domains;
    }

    protected function getDirectives()
    {
        $directives = [];

        array_map(function ($directive) use (&$directives) {
            $directives[$directive] = $this->getDomains();
        }, $this->getAvailableDirectives());

        return $directives;
    }

    protected function buildProfiles($profiles)
    {
        if (isset($profiles['profiles'])) {
            array_walk($profiles['profiles'], function ($v, $k) use (&$profiles) {
                $profiles['profiles'][$k] = $this->getDirectives();
            });
        }

        return $profiles;
    }

    protected function getProfileConfig($count = 4, $default = 'default', $jumbled = false)
    {
        $profiles = [
            'default' => $default,
            'profiles' => [
                $default => []
            ]
        ];

        for ($i = 0; $i < $count; $i++) {
            $profiles['profiles'][uniqid()] = [];
        }

        return $this->buildProfiles($profiles);
    }

    /**
     * Content security policy applied when original response does not contain
     * an existing policy, profile configuration, with default, is provided, and
     * profiles are specified.
     */
    public function testPolicyAppliedCondition1()
    {
        $existingPolicy = null;
        $profileConfig = $this->getProfileConfig();
        $profile = array_keys($profileConfig['profiles'])[0];
        $newPolicy = $this->middleware->getEncodedConfiguration($profileConfig['profiles'][$profile]);

        $original = $this->getResponseMock();
        $modified = $this->getResponseMock();
        $original->shouldReceive('getHeader')->andReturn([$existingPolicy]);
        $original->shouldReceive('withHeader')
            ->with($this->middleware->getHeader(), m::on(function ($policy) use ($newPolicy) {
                return $policy == $newPolicy;
            }))
            ->andReturn($modified);

        $response = $this->middleware
            ->addProfileConfiguration($profileConfig)
            ->handle($original, [$profile]);

        $this->assertEquals($modified, $response);
    }

    /**
     * Content security policy applied when original response does not contain
     * an existing policy, profile configuration, with default, is provided, and
     * no profiles are specified.
     */
    public function testPolicyAppliedCondition2()
    {
        $existingPolicy = null;
        $profileConfig = $this->getProfileConfig();
        $newPolicy = $this->middleware->getEncodedConfiguration($profileConfig['profiles']['default']);
        $original = $this->getResponseMock();
        $modified = $this->getResponseMock();
        $original->shouldReceive('getHeader')->andReturn([$existingPolicy]);
        $original->shouldReceive('withHeader')
            ->with($this->middleware->getHeader(), m::on(function ($policy) use ($newPolicy) {
                return $policy == $newPolicy;
            }))
            ->andReturn($modified);

        $response = $this->middleware
            ->addProfileConfiguration($profileConfig)
            ->handle($original);

        $this->assertEquals($modified, $response);
    }

    /**
     * Content security policy applied when original response does contain
     * an existing policy, profile configuration, without default, is provided,
     * and profiles are specified.
     */
    public function testPolicyAppliedCondition3()
    {
        $existingPolicy = "default-src 'self'; img-src 'self' data: blob: filesystem:; media-src mediastream:";
        $newPolicy = "default-src 'self' blob:; img-src 'self' blob: data: filesystem:; media-src mediastream:";
        $original = $this->getResponseMock();
        $modified = $this->getResponseMock();
        $original->shouldReceive('getHeader')->with($this->middleware->getHeader())->andReturn([$existingPolicy]);
        $original->shouldReceive('withHeader')
            ->with($this->middleware->getHeader(), m::on(function ($policy) use ($newPolicy) {
                return $policy == $newPolicy;
            }))
            ->andReturn($modified);

        $response = $this->middleware
            ->addProfileConfiguration(['profiles' => ['test' => ['default-src' => ["blob:"]]]])
            ->handle($original, ['test']);

        $this->assertEquals($modified, $response);
    }

    /**
     * Content security policy not applied when original response does not contain
     * an existing policy, no profile configuration is provided, and no profiles
     * are specified.
     */
    public function testPolicyNotAppliedCondition1()
    {
        $existingPolicy = null;
        $original = $this->getResponseMock();
        $original->shouldReceive('getHeader')->andReturn([$existingPolicy]);

        $response = $this->middleware
            ->handle($original);

        $this->assertEquals($original, $response);
    }

    /**
     * Content security policy not applied when original response does contain
     * an existing policy, no profile configuration is provided, and no profiles
     * are specified.
     */
    public function testPolicyNotAppliedCondition2()
    {
        $existingPolicy = "default-src 'self'; img-src 'self' data: blob: filesystem:; media-src mediastream:";
        $original = $this->getResponseMock();
        $original->shouldReceive('getHeader')->andReturn([$existingPolicy]);

        $response = $this->middleware
            ->handle($original);

        $this->assertEquals($original, $response);
    }

    /**
     * Content security policy not applied when original response does contain
     * an existing policy, profile configuration is provided, and no profiles
     * are specified.
     */
    public function testPolicyNotAppliedCondition3()
    {
        $existingPolicy = "default-src 'self'; img-src 'self' data: blob: filesystem:; media-src mediastream:";
        $original = $this->getResponseMock();
        $original->shouldReceive('getHeader')->with($this->middleware->getHeader())->andReturn([$existingPolicy]);

        $response = $this->middleware
            ->addProfileConfiguration(['profiles' => ['test' => ['default-src' => ["blob:"]]]])
            ->handle($original);

        $this->assertEquals($original, $response);
    }

    /**
     * Validation exceptions contain list of messages.
     */
    public function testValidationExceptionContainsMessages()
    {
        $profiles = ['default' => rand(0,10)];

        try {
            $v = GenericMiddleware::validateProfiles($profiles);
        } catch (CspValidationException $e) {
            $this->assertTrue(is_array($e->getMessages()));
        }
    }

    /**
     * Validation fails when default key defined and value is not string or array.
     * @expectedException Stevenmaguire\Http\Middleware\Exceptions\CspValidationException
     */
    public function testValidationFailsCondition1()
    {
        $profiles = ['default' => rand(0,10)];

        try {
            $v = GenericMiddleware::validateProfiles($profiles);
        } catch (CspValidationException $e) {
            $this->assertContains('Default profile configuration must be a string or array.', $e->getMessages());
            throw $e;
        }
    }

    /**
     * Validation fails when default key defined and value is array that contains any non-strings.
     * @expectedException Stevenmaguire\Http\Middleware\Exceptions\CspValidationException
     */
    public function testValidationFailsCondition2()
    {
        $profiles = ['default' => [uniqid(), uniqid(), rand(0,10)]];

        try {
            $v = GenericMiddleware::validateProfiles($profiles);
        } catch (CspValidationException $e) {
            $this->assertContains('Default profile configuration must contain only strings when defined as array.', $e->getMessages());
            throw $e;
        }
    }

    /**
     * Validation fails when profiles key defined and value is not array.
     * @expectedException Stevenmaguire\Http\Middleware\Exceptions\CspValidationException
     */
    public function testValidationFailsCondition3()
    {
        $profiles = ['profiles' => uniqid()];

        try {
            $v = GenericMiddleware::validateProfiles($profiles);
        } catch (CspValidationException $e) {
            $this->assertContains('Profile configuration must be an array.', $e->getMessages());
            throw $e;
        }
    }

    /**
     * Validation fails when profiles contain directives whose value is not array.
     * @expectedException Stevenmaguire\Http\Middleware\Exceptions\CspValidationException
     */
    public function testValidationFailsCondition4()
    {
        $profiles = ['profiles' => [
            'profile_one' => rand(0,10),
            'profile_two' => uniqid(),
            'profile_three' => rand(0,10),
            ]
        ];

        try {
            $v = GenericMiddleware::validateProfiles($profiles);
        } catch (CspValidationException $e) {
            array_walk($profiles['profiles'], function ($v, $k) use ($e) {
                $this->assertContains('Profile configuration for "'.$k.'" must be an array.', $e->getMessages());
            });
            throw $e;
        }
    }

    /**
     * Validation fails when profiles contain directives whose value is array and directives
     * not string or array.
     * @expectedException Stevenmaguire\Http\Middleware\Exceptions\CspValidationException
     */
    public function testValidationFailsCondition5()
    {
        $profiles = ['profiles' => [
            'profile_one' => [
                    'directive_one' => rand(0,10),
                    'directive_two' => new \stdClass,
                ],
            ]
        ];

        try {
            $v = GenericMiddleware::validateProfiles($profiles);
        } catch (CspValidationException $e) {
            array_walk($profiles['profiles'], function ($config, $profile) use ($e) {
                array_walk($config, function ($domains, $directive) use ($profile, $e) {
                    $this->assertContains('Directive configuration for "'.$profile.':'.$directive.'" must be a string or an array.', $e->getMessages());
                });
            });
            throw $e;
        }
    }

    /**
     * Validation succeds when configuration is empty array.
     */
    public function testValidationSucceedsCondition1()
    {
        $profiles = [];

        $this->assertTrue(
            GenericMiddleware::validateProfiles($profiles)
        );
    }


    /**
     * Validation succeds when default key is defined with string value.
     */
    public function testValidationSucceedsCondition2()
    {
        $profiles = ['default' => uniqid()];

        $this->assertTrue(
            GenericMiddleware::validateProfiles($profiles)
        );
    }

    /**
     * Validation succeds when default key is defined with array value.
     */
    public function testValidationSucceedsCondition3()
    {
        $profiles = ['default' => []];

        $this->assertTrue(
            GenericMiddleware::validateProfiles($profiles)
        );
    }

    /**
     * Validation succeds when profiles key is defined with array value.
     */
    public function testValidationSucceedsCondition4()
    {
        $profiles = ['profiles' => []];

        $this->assertTrue(
            GenericMiddleware::validateProfiles($profiles)
        );
    }

    /**
     * Validation succeds when profiles key is defined with array of profile arrays.
     */
    public function testValidationSucceedsCondition5()
    {
        $profiles = ['profiles' => [
            'profile_one' => [],
            'profile_two' => [],
        ]];

        $this->assertTrue(
            GenericMiddleware::validateProfiles($profiles)
        );
    }

    /**
     * Validation succeds when profiles key is defined with array of profile arrays
     * that contain directive strings or arrays.
     */
    public function testValidationSucceedsCondition6()
    {
        $profiles = ['profiles' => [
            'profile_one' => [
                'directive_one' => [],
                'directive_two' => uniqid(),
            ],
            'profile_two' => [
                'directive_one' => [],
                'directive_two' => uniqid(),
            ],
        ]];

        $this->assertTrue(
            GenericMiddleware::validateProfiles($profiles)
        );
    }
}
