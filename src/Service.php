<?php

namespace RetroChaos\VirusTotalApi;

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Helpers\FileHelper;
use RetroChaos\VirusTotalApi\Responses\DomainResponse;
use RetroChaos\VirusTotalApi\Responses\FileReportResponse;
use RetroChaos\VirusTotalApi\Responses\FileResponse;
use RetroChaos\VirusTotalApi\Responses\IpAddressResponse;

class Service
{
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
	 * @param string $filePath
	 * @param string|null $password
	 * @return FileReportResponse
	 */
	public function scanFile(string $filePath, ?string $password = null): FileReportResponse
	{
		$fileHandler = new FileHelper();
		if (!$fileHandler->isFileSizeValid($filePath)) {
			return new FileReportResponse(null, false, 'File size too large. Max 200MB allowed.');
		}

		$uploadUrl = 'files';
		if ($fileHandler->isLargeFile($filePath)) {
			$uploadUrl = $this->getLargeUploadUrl();
		}

		$response = $this->_httpClient->request('POST', $uploadUrl, [
			'multipart' => $fileHandler->prepareMultipartData($filePath, $password),
		]);

		if ($response['success']) {
			$fileResponse = new	FileResponse($response);
		} else {
			return new FileReportResponse(null, false, $response['message']);
		}

		try {
			return $this->getFileReport($fileResponse->getFileAnalysisId());
		} catch (PropertyNotFoundException $e) {
			return new FileReportResponse(null, false, 'File report not found!');
		}
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
}
