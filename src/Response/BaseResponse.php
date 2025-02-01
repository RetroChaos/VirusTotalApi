<?php

namespace RetroChaos\VirusTotalApi\Response;

class BaseResponse
{
	/**
	 * @var array|null $_data
	 */
	protected ?array $_data;

	/**
	 * @var int $_status
	 */
	protected int $_status;

	/**
	 * @var bool $_success
	 */
	protected bool $_success = true;

	/**
	 * @var string|null $_error_message
	 */
	protected ?string $_error_message = null;

	/**
	 * @var string|null
	 */
	protected ?string $_exception = null;

	/**
	 * @param array|null $data
	 * @param int $status
	 * @param bool $success
	 * @param string|null $message
	 * @param string|null $exception
	 */
	public function __construct(?array $data, int $status, bool $success = true, ?string $message = null, ?string $exception = null)
	{
		$this->_data = $data;
		$this->_status = $status;
		$this->_success = $success;
		$this->_error_message = $message;
		$this->_exception = $exception;
	}

	/**
	 * @return array|null
	 */
	public function getRawData(): ?array
	{
		return $this->_data;
	}

	/**
	 * @return string
	 */
	public function getJsonData(): string
	{
		return json_encode($this->_data);
	}

	/**
	 * @return bool
	 */
	public function isSuccessful(): bool
	{
		return $this->_success;
	}

	/**
	 * @return string|null
	 */
	public function getErrorMessage(): ?string
	{
		return $this->_error_message;
	}

	/**
	 * @return string|null
	 */
	public function getException(): ?string
	{
		return $this->_exception;
	}

	/**
	 * @return int
	 */
	public function getStatusCode(): int
	{
		return $this->_status;
	}

}