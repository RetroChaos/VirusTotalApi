<?php

namespace RetroChaos\VirusTotalApi\Helper;

class FileHelper
{
	private const MAX_FILE_SIZE_MB = 200;
	private const LARGE_FILE_SIZE_MB = 32;

	/**
	 * Checks if the filesize is less than 200MB
	 * @param string $filePath
	 * @return bool
	 */
	public function isFileSizeValid(string $filePath): bool
	{
		return filesize($filePath) / (1024 ** 2) < self::MAX_FILE_SIZE_MB;
	}

	/**
	 * Checks if the file is a 'large' file, that is, greater than or equal to 32MB
	 * @param string $filePath
	 * @return bool
	 */
	public function isLargeFile(string $filePath): bool
	{
		return filesize($filePath) / (1024 ** 2) >= self::LARGE_FILE_SIZE_MB;
	}

	/**
	 * Prepares the POST data for submitting files
	 * @param string $filePath
	 * @param string|null $password
	 * @return array[]
	 */
	public function prepareMultipartData(string $filePath, ?string $password = null): array
	{
		$multipart = [
			[
				'name' => 'file',
				'filename' => basename($filePath),
				'contents' => fopen($filePath, 'r'),
				'headers' => [
					'Content-Type' => mime_content_type($filePath) ?: 'application/octet-stream',
				],
			],
		];

		if ($password !== null) {
			$multipart[] = [
				'name' => 'password',
				'contents' => $password,
			];
		}

		return $multipart;
	}
}
