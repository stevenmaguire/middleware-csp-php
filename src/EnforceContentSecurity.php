<?php namespace Stevenmaguire\Http\Middleware;

use Psr\Http\Message\ResponseInterface;

class EnforceContentSecurity
{
    /**
     * Configuration for session
     *
     * @var array
     */
    private $config = [];

    /**
     * Directive separator
     *
     * @var string
     */
    private $directiveSeparator = ';';

   /**
     * Security header name
     *
     * @var string
     */
    private $header = 'Content-Security-Policy';

    /**
     * Profiles
     *
     * @var array
     */
    private $profiles = [];


    /**
     * Source separator
     *
     * @var string
     */
    private $sourceSeparator = ' ';

    /**
     * Add content security policy header to response
     *
     * @param  ResponseInterface  $response
     *
     * @return ResponseInterface
     */
    protected function addPolicyHeader(ResponseInterface $response)
    {
        $this->loadDefaultProfiles();

        $initialConfig = $this->decodeConfiguration(
            (string) $response->getHeader($this->header)
        );

        $initialDirectives = $this->encodeConfiguration($initialConfig);

        $this->mergeProfileWithConfig($initialConfig);

        $newDirectives = $this->encodeConfiguration($this->config);

        if ($newDirectives != $initialDirectives) {
            $response = $response->withHeader($this->header, $newDirectives);
        }

        return $response;
    }

    /**
     * Decode a given string into configuration
     *
     * @param  string $string
     *
     * @return array
     */
    protected function decodeConfiguration($string)
    {
        $config = [];
        $directives = explode($this->directiveSeparator, $string);
        foreach ($directives as $directive) {
            $parts = array_filter(explode($this->sourceSeparator, $directive));
            $key = trim(array_shift($parts));
            $config[$key] = $parts;
        }

        return $config;
    }

    /**
     * Encode the current configuration as string
     *
     * @param  array $config
     *
     * @return string
     */
    protected function encodeConfiguration($config = [])
    {
        $value = [];
        ksort($config);
        foreach ($config as $directive => $values) {
            $values = array_unique($values);
            sort($values);
            array_unshift($values, $directive);
            $string = implode($this->sourceSeparator, $values);

            if ($string) {
                $value[] = $string;
            }
        }

        return implode($this->directiveSeparator . ' ', $value);
    }


    /**
     * Create array from value
     *
     * @param  mixed $value
     *
     * @return array
     */
    protected function getArrayFromValue($value, $separator = ',')
    {
        if (!is_array($value)) {
            $value = explode($separator, $value);
        }

        return $value;
    }

    /**
     * Gets header.
     *
     * @return string
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Load default profiles
     *
     * @return void
     */
    protected function loadDefaultProfiles()
    {
        $defaultProfiles = [];

        if (isset($this->profiles['default'])) {
            $defaultProfiles = $this->getArrayFromValue(
                $this->profiles['default']
            );
        }

        array_map([$this, 'loadProfileByKey'], $defaultProfiles);
    }

    /**
     * Load a specific profile
     *
     * @param  string $key
     *
     * @return void
     */
    protected function loadProfileByKey($key)
    {
        if (isset($this->profiles['profiles'][$key])) {
            $profile = $this->profiles['profiles'][$key];

            if (is_array($profile)) {
                $this->mergeProfileWithConfig($profile);
            }
        }
    }

    /**
     * Merge a given profile with current configuration
     *
     * @param  array $profile
     *
     * @return void
     */
    protected function mergeProfileWithConfig(array $profile)
    {
        foreach ($profile as $directive => $values) {
            if (!isset($this->config[$directive])) {
                $this->config[$directive] = [];
            }

            $values = $this->getArrayFromValue($values);

            $this->config[$directive] = array_merge($this->config[$directive], $values);
        }
    }

    /**
     * Sets profiles.
     *
     * @param array  $profiles
     *
     * @return EnforceContentSecurity
     */
    protected function setProfiles($profiles = [])
    {
        $this->profiles = $profiles;

        return $this;
    }
}
