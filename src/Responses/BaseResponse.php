<?php

namespace RetroChaos\VirusTotalApi\Responses;

class BaseResponse
{
	/**
	 * @var array|null $_response
	 */
	protected ?array $_response = null;

	/**
	 * @var bool
	 */
	protected bool $_success;

	/**
	 * @var string $_message
	 */
	protected string $_message = '';

	/**
	 * @param array|null $response
	 * @param bool $success
	 * @param string $message
	 */
	public function __construct(?array $response, bool $success = true, string $message = '')
	{
		$this->_response = $response;
		$this->_success = $success;
		$this->_message = $message;
	}

	/**
	 * @return array|null
	 */
	public function getRawResponse(): ?array
	{
		return $this->_response;
	}

	/**
	 * @return string
	 */
	public function getJsonResponse(): string
	{
		return json_encode($this->_response);
	}

	/**
	 * @return bool
	 */
	public function isSuccessful(): bool
	{
		return $this->_success;
	}

	/**
	 * @return string
	 */
	public function getErrorMessage(): string
	{
		return $this->_message;
	}
}