<?php

namespace RetroChaos\VirusTotalApi\Response;

use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;

class FileResponse extends BaseResponse {
	/**
	 * Gets the analysis ID for a scanned file.
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getFileAnalysisId(): string
	{
		if (!isset($this->_response['data']['id'])) {
			throw new PropertyNotFoundException("No analysis ID found!");
		}

		return $this->_response['data']['id'];
	}
}