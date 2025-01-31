<?php

namespace RetroChaos\VirusTotalApi;

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Helpers\FileHelper;

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
	 * @param string $filePath
	 * @param string|null $password
	 * @return array
	 */
	public function scanFile(string $filePath, ?string $password = null): array
	{
		$fileHandler = new FileHelper();
		if (!$fileHandler->isFileSizeValid($filePath)) {
			return [
				'success' => false,
				'message' => "File size too large. Max 200MB allowed.",
			];
		}

		$uploadUrl = 'files';
		if ($fileHandler->isLargeFile($filePath)) {
			$uploadUrl = $this->getLargeUploadUrl();
		}

		return $this->_httpClient->request('POST', $uploadUrl, [
			'multipart' => $fileHandler->prepareMultipartData($filePath, $password),
		]);
	}

	/**
	 * Gets the analysis ID for a scanned file.
	 * @param array $response
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getFileAnalysisId(array $response): string
	{
		if (!isset($response['data']['id'])) {
			throw new PropertyNotFoundException("No analysis ID found!");
		}

		return $response['data']['id'];
	}

	/**
	 * Gets the analysis report of a file.
	 * @param string $analysisId
	 * @return array
	 */
	public function getFileReport(string $analysisId): array
	{
		return $this->_httpClient->request('GET', "analyses/$analysisId");
	}

	public function scanIpAddress(string $ipAddress): array
	{
		return $this->_httpClient->request('GET', "ip_addresses/$ipAddress");
	}

	public function scanDomain(string $domain): array
	{
		return $this->_httpClient->request('GET', "domains/$domain");
	}
}
