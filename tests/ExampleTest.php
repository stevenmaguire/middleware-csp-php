<?php namespace Stevenmaguire\Http\Middleware\Test;

use Mockery as m;

class ExampleTest extends \PHPUnit_Framework_TestCase
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
        return [
            'base-uri','child-src','connect-src','default-src','font-src',
            'form-action','frame-ancestors','frame-src','img-src','manifest-src',
            'media-src','object-src','plugin-types','referrer','reflected-xss',
            'report-uri','sandbox','script-src','style-src','upgrade-insecure-requests',
        ];
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
        $original->shouldReceive('getHeader')->andReturn($existingPolicy);
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
        $original->shouldReceive('getHeader')->andReturn($existingPolicy);
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
        $original->shouldReceive('getHeader')->with($this->middleware->getHeader())->andReturn($existingPolicy);
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
        $original->shouldReceive('getHeader')->andReturn($existingPolicy);

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
        $original->shouldReceive('getHeader')->andReturn($existingPolicy);

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
        $original->shouldReceive('getHeader')->with($this->middleware->getHeader())->andReturn($existingPolicy);

        $response = $this->middleware
            ->addProfileConfiguration(['profiles' => ['test' => ['default-src' => ["blob:"]]]])
            ->handle($original);

        $this->assertEquals($original, $response);
    }
}
