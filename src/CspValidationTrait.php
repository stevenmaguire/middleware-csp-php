<?php namespace Stevenmaguire\Http\Middleware;

trait CspValidationTrait
{
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
                            $messages[] = 'Directive configuration for "'.$profile.':'.$directive.'"'.
                                ' must be a string or an array.';
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
