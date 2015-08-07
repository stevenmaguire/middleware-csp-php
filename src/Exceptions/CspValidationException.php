<?php namespace Stevenmaguire\Http\Middleware\Exceptions;

use Exception;

class CspValidationException extends Exception
{
    /**
     * Validation messages
     *
     * @var array
     */
    protected $messages;

    /**
     * Creates new validation exception for content security.
     *
     * @param array  $messages
     */
    public function __construct($messages = [])
    {
        parent::__construct(
            "The profile configuration provided did not meet the validation requirements",
            400
        );
        $this->messages = $messages;
    }

    /**
     * Retrives validation messages from exception.
     *
     * @return array
     */
    public function getMessages()
    {
        return $this->messages;
    }
}
