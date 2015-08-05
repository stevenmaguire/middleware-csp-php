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
