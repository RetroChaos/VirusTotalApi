<?php

namespace RetroChaos\VirusTotalApi\Api;

use RetroChaos\VirusTotalApi\Analyser\FileAnalyser;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Helper\FileHelper;
use RetroChaos\VirusTotalApi\Response\FileReportResponse;
use RetroChaos\VirusTotalApi\Response\FileResponse;

class FileApi extends BaseApi
{
	/**
	 * Gets the upload URL fpr large files.
	 * @return string
	 */
	public function getLargeUploadUrl(): string
	{
		$response = $this->_httpClient->request('GET', 'files/upload_url');
		return $response['success'] ? $response['contents']['data'] : '';
	}

	/**
	 * Uploads a file to VirusTotal for scanning
	 * @param string $filePath
	 * @param string|null $password
	 * @return FileResponse
	 */
	public function uploadFile(string $filePath, ?string $password = null): FileResponse
	{
		$fileHelper = new FileHelper();
		if (!$fileHelper->isFileSizeValid($filePath)) {
			return new FileResponse(null, 400,  false, 'File size too large. Max 200MB allowed.', 'FileTooLarge');
		}

		$uploadUrl = $fileHelper->isLargeFile($filePath) ? $this->getLargeUploadUrl() : 'files';

		$response = $this->_httpClient->request('POST', $uploadUrl, [
			'multipart' => $fileHelper->prepareMultipartData($filePath, $password),
		]);

		if ($response['success']) {
			return new FileResponse($response['contents'], $response['status_code']);
		} else {
			return new FileResponse($response['contents'], $response['status_code'], $response['success'], $response['error_message'], $response['exception']);
		}
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
			return new FileReportResponse($response['contents'], $response['status_code']);
		} else {
			return new FileReportResponse($response['contents'], $response['status_code'], $response['success'], $response['error_message'], $response['exception']);
		}
	}

	public function scanUntilCompleted(string $id, int $step = 15, int $maxAttempts = 5, int $initialDelay = 0): FileReportResponse
	{
		try {
			$attempt = 0;
			$delay = $initialDelay;

			do {
				sleep($delay);

				$report = $this->getFileReport($id);
				$analyser = new FileAnalyser($report);
				$status = $analyser->getStatus();

				if ($status === 'completed') {
					return new FileReportResponse($report->getRawData(), $report->getStatusCode());
				}

				++$attempt;
				$delay = min($delay + $step, 60); // Linear increase but capped at 60 seconds
			} while ($attempt < $maxAttempts);

			return new FileReportResponse(null, 408, false, 'Timeout waiting for file scan to complete', 'ScanTimeout');

		} catch (PropertyNotFoundException $e) {
			return new FileReportResponse(null, 400, false, $e->getMessage(), 'FileReportNotFound');
		}
	}

	/**
	 * @param string $id
	 * @param bool $isMalicious
	 * @return void
	 */
	public function voteFile(string $id, bool $isMalicious): void
	{
		$this->_httpClient->request('POST', "files/$id/votes", [
			"body" => json_encode($isMalicious ? self::MALICIOUS_VOTE_BODY : self::HARMLESS_VOTE_BODY),
			"headers" => ['Content-Type' => 'application/json'],
		]);
	}

	/**
	 * @param string $id
	 * @return void
	 */
	public function rescanFile(string $id): void
	{
		$this->_httpClient->request('POST', "files/$id/analyse");
	}
}