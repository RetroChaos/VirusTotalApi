<?php

namespace RetroChaos\VirusTotalApi;

use RetroChaos\VirusTotalApi\Api\DomainApi;
use RetroChaos\VirusTotalApi\Api\FileApi;
use RetroChaos\VirusTotalApi\Api\IpApi;
use RetroChaos\VirusTotalApi\Exception\NoIdSetException;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Helper\ScanHelper;
use RetroChaos\VirusTotalApi\Response\DomainResponse;
use RetroChaos\VirusTotalApi\Response\FileReportResponse;
use RetroChaos\VirusTotalApi\Response\IpAddressResponse;

class Service
{
	/**
	 * @var FileApi $_fileApi
	 */
	private FileApi $_fileApi;

	/**
	 * @var DomainApi
	 */
	private DomainApi $_domainApi;

	/**
	 * @var IpApi $_ipApi
	 */
	private IpApi $_ipApi;

	/**
	 * The main service class handling API calls.
	 * @param HttpClient $httpClient
	 */
	public function __construct(HttpClient $httpClient)
	{
		$this->_fileApi = new FileApi($httpClient);
		$this->_domainApi = new DomainApi($httpClient);
		$this->_ipApi = new IpApi($httpClient);
	}

	/**
	 * Scans a file, doesn't wait until the status is 'completed'.
	 * @param string $filePath
	 * The absolute filepath
	 * @param string|null $password
	 * Password optional
	 * @return FileReportResponse
	 */
	public function scanFile(string $filePath, ?string $password = null): FileReportResponse
	{
		$fileResponse = $this->_fileApi->uploadFile($filePath, $password);

		if (!$fileResponse->isSuccessful()) {
			return new FileReportResponse(null, false, $fileResponse->getErrorMessage());
		}

		$scanHelper = new ScanHelper();
		try {
			$id = $scanHelper->getFileId($fileResponse);
		} catch (NoIdSetException|PropertyNotFoundException $e) {
			return new FileReportResponse(null, false, $e->getMessage());
		}

		return $this->_fileApi->getFileReport($id);
	}

	/**
	 * Scans a file, waits until the status is 'completed'.
	 * @param string $filePath
	 * The absolute filepath
	 * @param string|null $password
	 * Password optional.
	 * @param int $maxAttempts
	 * Max attempts before failure.
	 * @param int $initialDelay
	 * Offset before starting scanning. Defaults to zero.
	 * @param int $step
	 * Increment steps between each call. Defaults to 15s
	 * @return FileReportResponse
	 */
	public function scanFileUntilCompleted(string $filePath, ?string $password = null, int $step = 15, int $maxAttempts = 5, int $initialDelay = 0): FileReportResponse
	{
		$fileResponse = $this->_fileApi->uploadFile($filePath, $password);

		if (!$fileResponse->isSuccessful()) {
			return new FileReportResponse($fileResponse->getRawData(), $fileResponse->getStatusCode(), $fileResponse->isSuccessful(), $fileResponse->getErrorMessage(), $fileResponse->getException());
		}

		$scanHelper = new ScanHelper();
		try {
			$id = $scanHelper->getFileId($fileResponse);
		} catch (NoIdSetException|PropertyNotFoundException $e) {
			$exception  = ($e instanceof PropertyNotFoundException) ? 'PropertyNotFound' : 'NoIdSet';
			return new FileReportResponse(null, 400, false, $e->getMessage(), $exception);
		}

		return $this->_fileApi->scanUntilCompleted($id, $step, $maxAttempts, $initialDelay);
	}

	/**
	 * @param string $ipAddress
	 * @return IpAddressResponse
	 */
	public function scanIpAddress(string $ipAddress): IpAddressResponse
	{
		return $this->_ipApi->getIpReport($ipAddress);
	}

	/**
	 * @param string $domain
	 * @return DomainResponse
	 */
	public function scanDomain(string $domain): DomainResponse
	{
		return $this->_domainApi->getDomainReport($domain);
	}

	/**
	 * @param string $domain
	 * @return void
	 */
	public function addHarmlessDomainVote(string $domain): void
	{
		$this->_domainApi->voteDomain($domain, false);
	}

	/**
	 * @param string $domain
	 * @return void
	 */
	public function addMaliciousDomainVote(string $domain): void
	{
		$this->_domainApi->voteDomain($domain, true);
	}

	/**
	 * @param string $ipAddress
	 * @return void
	 */
	public function addHarmlessIpVote(string $ipAddress): void
	{
		$this->_ipApi->voteIp($ipAddress, false);
	}

	/**
	 * @param string $ipAddress
	 * @return void
	 */
	public function addMaliciousIpVote(string $ipAddress): void
	{
		$this->_ipApi->voteIp($ipAddress, true);
	}

	/**
	 * @param string $id
	 * Must either be SHA-256, SHA-1 or MD5 hash identifying the file.
	 * Easy to pass the id returned from FileAnalyser::getFileId()
	 * @return void
	 */
	public function addHarmlessFileVote(string $id): void
	{
		$this->_fileApi->voteFile($id, false);
	}

	/**
	 * @param string $id
	 * Must either be SHA-256, SHA-1 or MD5 hash identifying the file.
	 * Easy to pass the id returned from FileAnalyser::getFileId()
	 * @return void
	 */
	public function addMaliciousFileVote(string $id): void
	{
		$this->_fileApi->voteFile($id, true);
	}

	/**
	 * @param string $domain
	 * @return void
	 */
	public function rescanDomain(string $domain): void
	{
		$this->_domainApi->rescanDomain($domain);
	}

	public function rescanIp(string $ipAddress): void
	{
		$this->_ipApi->rescanIpAddress($ipAddress);
	}

	/**
	 * @param string $id
	 * Must either be SHA-256, SHA-1 or MD5 hash identifying the file.
	 * Easy to pass the id returned from FileAnalyser::getFileId()
	 * @return void
	 */
	public function rescanFile(string $id): void
	{
		$this->_fileApi->rescanFile($id);
	}
}
