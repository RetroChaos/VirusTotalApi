<?php

namespace RetroChaos\VirusTotalApi\Helper;

use RetroChaos\VirusTotalApi\Analyser\FileAnalyser;
use RetroChaos\VirusTotalApi\Exception\NoIdSetException;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Response\FileReportResponse;
use RetroChaos\VirusTotalApi\Response\FileResponse;

class ScanHelper
{
	/**
	 * @param $fileId
	 * Can either pass in a FileResponse to get the ID, or just pass the ID itself.
	 * @return string
	 * @throws NoIdSetException
	 * @throws PropertyNotFoundException
	 */
	public function getFileId($fileId): string
	{
		if ($fileId instanceof FileResponse) {
			$id = $fileId->getFileAnalysisId();
		} elseif(is_string($fileId)) {
			$id = $fileId;
		} else {
			throw new NoIdSetException('File ID must be string or FileResponse instance.');
		}

		return $id;
	}
}