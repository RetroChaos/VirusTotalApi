<?php

namespace RetroChaos\VirusTotalApi;

use RetroChaos\VirusTotalApi\Analysers\FileAnalyser;
use RetroChaos\VirusTotalApi\Exceptions\NoIdSetException;
use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Helpers\FileHelper;
use RetroChaos\VirusTotalApi\Helpers\ScanHelper;
use RetroChaos\VirusTotalApi\Responses\DomainResponse;
use RetroChaos\VirusTotalApi\Responses\FileReportResponse;
use RetroChaos\VirusTotalApi\Responses\FileResponse;
use RetroChaos\VirusTotalApi\Responses\IpAddressResponse;

class Service
{
	const HARMLESS_VOTE_BODY = [
		"data" => [
			"type" => "vote",
			"attributes" => [
				"verdict" => "harmless"
			]
		]
	];

	const MALICIOUS_VOTE_BODY = [
		"data" => [
			"type" => "vote",
			"attributes" => [
				"verdict" => "malicious"
			]
		]
	];

	/**
	 * @var HttpClient $_httpClient
	 */
	private HttpClient $_httpClient;

	/**
	 * The main service class handling API calls.
	 * @param HttpClient $httpClient
	 */
	public function __construct(HttpClient $httpClient)
	{
		$this->_httpClient = $httpClient;
	}

	/**
	 * Gets the upload URL fpr large files.
	 * @return string
	 */
	public function getLargeUploadUrl(): string
	{
		$response = $this->_httpClient->request('GET', 'files/upload_url');
		return $response['success'] ? $response['data'] : '';
	}

	/**
	 * Gets the analysis report of a file.
	 * @param string $analysisId
	 * @return FileReportResponse
	 */
	public function getFileReport(string $analysisId): FileReportResponse
	{
		$response = $this->_httpClient->request('GET', "analyses/$analysisId");
		if ($response['success']) {
			return new FileReportResponse($response);
		} else {
			return new FileReportResponse(null, false, $response['message']);
		}
	}

	/**
	 * Uploads a file to VirusTotal for scanning
	 * @param string $filePath
	 * @param string|null $password
	 * @return FileResponse
	 */
	public function uploadForScanning(string $filePath, ?string $password = null): FileResponse
	{
		$fileHandler = new FileHelper();
		if (!$fileHandler->isFileSizeValid($filePath)) {
			return new FileResponse(null, false, 'File size too large. Max 200MB allowed.');
		}

		$uploadUrl = 'files';
		if ($fileHandler->isLargeFile($filePath)) {
			$uploadUrl = $this->getLargeUploadUrl();
		}

		$response = $this->_httpClient->request('POST', $uploadUrl, [
			'multipart' => $fileHandler->prepareMultipartData($filePath, $password),
		]);

		if ($response['success']) {
			return new FileResponse($response);
		} else {
			return new FileResponse(null, false, $response['message']);
		}
	}

	/**
	 * Scans a file, doesn't wait until the status is 'completed'
	 * @param string $filePath
	 * @param string|null $password
	 * @return FileReportResponse
	 */
	public function scanFile(string $filePath, ?string $password = null): FileReportResponse
	{
		$fileResponse = $this->uploadForScanning($filePath, $password);

		if (!$fileResponse->isSuccessful()) {
			return new FileReportResponse(null, false, $fileResponse->getErrorMessage());
		}

		$scanHelper = new ScanHelper();
		try {
			$id = $scanHelper->getFileId($fileResponse);
		} catch (NoIdSetException|PropertyNotFoundException $e) {
			return new FileReportResponse(null, false, $e->getMessage());
		}

		return $this->getFileReport($id);
	}

	/**
	 * @param string $id
	 * @param int $sleep
	 * Sleeps by default for 15s as the free version of VirusTotal API only allows 5 requests per minute!
	 * @return FileReportResponse
	 */
	public function scanUntilCompleted(string $id, int $sleep = 15): FileReportResponse
	{
		try {
			$report = $this->getFileReport($id);
			$analyser = new FileAnalyser($report);
			$status = $analyser->getStatus();
			while ($status !== 'completed') {
				sleep($sleep);
				$report = $this->getFileReport($id);
				$analyser->setReport($report);
				$status = $analyser->getStatus();
			}
			return new FileReportResponse($report->getRawResponse());
		} catch (PropertyNotFoundException $e) {
			return new FileReportResponse(null, false, 'File report not found!');
		}
	}

	/**
	 * @param string $filePath
	 * @param string|null $password
	 * @param int $sleep Sleeps by default for 15s as the free version of VirusTotal API only allows 5 requests per minute!
	 * @return FileReportResponse
	 */
	public function scanFileUntilCompleted(string $filePath, ?string $password = null, int $sleep = 15): FileReportResponse
	{
		$fileResponse = $this->uploadForScanning($filePath, $password);

		if (!$fileResponse->isSuccessful()) {
			return new FileReportResponse(null, false, $fileResponse->getErrorMessage());
		}

		$scanHelper = new ScanHelper();
		try {
			$id = $scanHelper->getFileId($fileResponse);
		} catch (NoIdSetException|PropertyNotFoundException $e) {
			return new FileReportResponse(null, false, $e->getMessage());
		}

		return $this->scanUntilCompleted($id, $sleep);
	}

	/**
	 * @param string $ipAddress
	 * @return IpAddressResponse
	 */
	public function scanIpAddress(string $ipAddress): IpAddressResponse
	{
		$response = $this->_httpClient->request('GET', "ip_addresses/$ipAddress");
		if ($response['success']) {
			return new IpAddressResponse($response);
		} else {
			return new IpAddressResponse(null, false, $response['message']);
		}
	}

	/**
	 * @param string $domain
	 * @return DomainResponse
	 */
	public function scanDomain(string $domain): DomainResponse
	{
		$response = $this->_httpClient->request('GET', "domains/$domain");
		if ($response['success']) {
			return new DomainResponse($response);
		} else {
			return new DomainResponse(null, false, $response['message']);
		}
	}

	/**
	 * @param string $domain
	 * @return void
	 */
	public function addHarmlessDomainVote(string $domain): void
	{
		$this->_httpClient->request('POST', "domains/$domain/votes", [
			"body" => json_encode(self::HARMLESS_VOTE_BODY),
			"headers" => ['Content-Type' => 'application/json'],
		]);
	}

	/**
	 * @param string $domain
	 * @return void
	 */
	public function addMaliciousDomainVote(string $domain): void
	{
		$this->_httpClient->request('POST', "domains/$domain/votes", [
			"body" => json_encode(self::MALICIOUS_VOTE_BODY),
			"headers" => ['Content-Type' => 'application/json'],
		]);
	}

	/**
	 * @param string $ipAddress
	 * @return void
	 */
	public function addHarmlessIpVote(string $ipAddress): void
	{
		$this->_httpClient->request('POST', "ip_addresses/$ipAddress/votes", [
			"body" => json_encode(self::HARMLESS_VOTE_BODY),
			"headers" => ['Content-Type' => 'application/json'],
		]);
	}

	/**
	 * @param string $ipAddress
	 * @return void
	 */
	public function addMaliciousIpVote(string $ipAddress): void
	{
		$this->_httpClient->request('POST', "ip_addresses/$ipAddress/votes", [
			"body" => json_encode(self::MALICIOUS_VOTE_BODY),
			"headers" => ['Content-Type' => 'application/json'],
		]);
	}
}
