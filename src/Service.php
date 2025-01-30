<?php

namespace RetroChaos\VirusTotalApi;

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;

class Service
{
	/**
	 * @var HttpClient $_httpClient
	 */
	private HttpClient $_httpClient;

	/**
	 * Constructor
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
		$fileHandler = new FileScanner();
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
	public function getAnalysisId(array $response): string
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

	/**
	 * Returns a simple bool if both the malicious and suspicious counts are zero.
	 * @param array $report
	 * @return bool
	 */
	public function isFileSafe(array $report): bool
	{
		try {
			return !($this->getMaliciousCount($report) > 0 || $this->getSuspiciousCount($report) > 0);
		} catch (PropertyNotFoundException $e) {
			return false;
		}
	}

	/**
	 * @param array $report
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getMaliciousCount(array $report): int
	{
		if (!isset($report['data']['attributes']['stats']['malicious'])) {
			throw new PropertyNotFoundException("Malicious count not set in the report!");
		}

		return $report['data']['attributes']['stats']['malicious'];
	}

	/**
	 * @param array $report
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getSuspiciousCount(array $report): int
	{
		if (!isset($report['data']['attributes']['stats']['suspicious'])) {
			throw new PropertyNotFoundException("Suspicious count not set in the report!");
		}

		return $report['data']['attributes']['stats']['suspicious'];
	}

	/**
	 * @param array $report
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getUndetectedCount(array $report): int
	{
		if (!isset($report['data']['attributes']['stats']['undetected'])) {
			throw new PropertyNotFoundException("Undetected count not set in the report!");
		}

		return $report['data']['attributes']['stats']['undetected'];
	}

	/**
	 * @param array $report
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getHarmlessCount(array $report): int
	{
		if (!isset($report['data']['attributes']['stats']['harmless'])) {
			throw new PropertyNotFoundException("Harmless count not set in the report!");
		}

		return $report['data']['attributes']['stats']['harmless'];
	}

	/**
	 * @param array $report
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getTimeoutCount(array $report): int
	{
		if (!isset($report['data']['attributes']['stats']['timeout'])) {
			throw new PropertyNotFoundException("Timeout count not set in the report!");
		}

		return $report['data']['attributes']['stats']['timeout'];
	}

	/**
	 * @param array $report
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getFailureCount(array $report): int
	{
		if (!isset($report['data']['attributes']['stats']['failure'])) {
			throw new PropertyNotFoundException("Failure count not set in the report!");
		}

		return $report['data']['attributes']['stats']['failure'];
	}

	/**
	 * @param array $report
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getTypeUnsupportedCount(array $report): int
	{
		if (!isset($report['data']['attributes']['stats']['type-unsupported'])) {
			throw new PropertyNotFoundException("Type Unsupported count not set in the report!");
		}

		return $report['data']['attributes']['stats']['type-unsupported'];
	}
}