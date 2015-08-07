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

        $currentHeader = $response->getHeader($this->header);

        $initialConfig = [];
        if (count($currentHeader)) {
            $initialConfig = $this->decodeConfiguration($currentHeader[0]);
        }

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
     * Retrieves array of currently configured content security policy directives.
     *
     * @return array
     */
    public static function getAvailableDirectives()
    {
        return [
            '\'self\'', 'base-uri','child-src','connect-src','default-src','font-src',
            'form-action','frame-ancestors','frame-src','img-src','manifest-src',
            'media-src','object-src','plugin-types','referrer','reflected-xss',
            'report-uri','sandbox','script-src','style-src','upgrade-insecure-requests',
        ];
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

    /**
     * Validates a given profiles configuration.
     *
     * @param  array   $profiles
     *
     * @return boolean
     * @throws CspValidationException
     */
    public static function validateProfiles(array $profiles)
    {
        $messages = [];

        if (isset($profiles['default'])) {
            static::validateProfilesDefault($profiles['default'], $messages);
        }

        if (isset($profiles['profiles'])) {
            static::validateProfilesConfiguration($profiles['profiles'], $messages);
        }

        if (empty($messages)) {
            return true;
        }

        throw new Exceptions\CspValidationException($messages);
    }

    /**
     * Validates a given default configuration.
     *
     * @param  mixed   $default
     * @param  array   $messages
     *
     * @return void
     */
    public static function validateProfilesDefault($default, array &$messages)
    {
        if (static::isNotArrayOrString($default)) {
            $messages[] = 'Default profile configuration must be a string or array.';
        }

        if (is_array($default) && count(array_filter($default, [__CLASS__, 'isNotString']))) {
            $messages[] = 'Default profile configuration must contain only strings when defined as array.';
        }
    }

    /**
     * Validates a given profiles configuration.
     *
     * @param  mixed   $profiles
     * @param  array   $messages
     *
     * @return void
     */
    public static function validateProfilesConfiguration($profiles, array &$messages)
    {
        if (static::isNotArray($profiles)) {
            $messages[] = 'Profile configuration must be an array.';
        } else {
            array_walk($profiles, function ($config, $profile) use (&$messages) {
                if (static::isNotArray($config)) {
                    $messages[] = 'Profile configuration for "'.$profile.'" must be an array.';
                } else {
                    array_walk($config, function ($domains, $directive) use ($profile, &$messages) {
                        if (static::isNotArrayOrString($domains)) {
                            $messages[] = 'Directive configuration for "'.$profile.':'.$directive.'" must be a string or an array.';
                        }
                    });
                }
            });
        }
    }

    /**
     * Determines if given subject is not an array.
     *
     * @param  mixed
     *
     * @return boolean
     */
    protected static function isNotArray($subject)
    {
        return !is_array($subject);
    }

    /**
     * Determines if given subject is not an array and not a string.
     *
     * @param  mixed
     *
     * @return boolean
     */
    protected static function isNotArrayOrString($subject)
    {
        return static::isNotString($subject) && static::isNotArray($subject);
    }

    /**
     * Determines if given subject is not a string.
     *
     * @param  mixed
     *
     * @return boolean
     */
    protected static function isNotString($subject)
    {
        return !is_string($subject);
    }
}
