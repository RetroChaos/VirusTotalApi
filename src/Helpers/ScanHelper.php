<?php

namespace RetroChaos\VirusTotalApi\Helpers;

use RetroChaos\VirusTotalApi\Analysers\FileAnalyser;
use RetroChaos\VirusTotalApi\Exceptions\NoIdSetException;
use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Responses\FileReportResponse;
use RetroChaos\VirusTotalApi\Responses\FileResponse;

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