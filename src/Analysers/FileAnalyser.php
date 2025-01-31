<?php

namespace RetroChaos\VirusTotalApi\Analysers;

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Responses\FileReportResponse;

class FileAnalyser extends BaseAnalyser
{
	/**
	 * Only accepts FileReportResponse to avoid passing in any array.
	 * @param FileReportResponse $report
	 */
	public function __construct(FileReportResponse $report)
	{
		$this->_report = $report->getRawResponse();
	}

	/**
	 * In case you need to change the report response but don't necessarily want to create a new analyser object.
	 * @param FileReportResponse $report
	 * @return $this
	 */
	public function setReport(FileReportResponse $report): self
	{
		$this->_report = $report->getRawResponse();
		return $this;
	}

	/**
	 * Returns true if both malicious count and suspicious count is zero.
	 * @return bool
	 */
	public function isFileSafe(): bool
	{
		try {
			return $this->getMaliciousCount() === 0 && $this->getSuspiciousCount() === 0;
		} catch (PropertyNotFoundException $e) {
			return false;
		}
	}

	/**
	 * @throws PropertyNotFoundException
	 */
	public function getMaliciousCount(): int
	{
		return $this->_getStat('malicious');
	}

	/**
	 * @throws PropertyNotFoundException
	 */
	public function getSuspiciousCount(): int
	{
		return $this->_getStat('suspicious');
	}

	/**
	 * @throws PropertyNotFoundException
	 */
	public function getUndetectedCount(): int
	{
		return $this->_getStat('undetected');
	}

	/**
	 * @throws PropertyNotFoundException
	 */
	public function getHarmlessCount(): int
	{
		return $this->_getStat('harmless');
	}

	/**
	 * @throws PropertyNotFoundException
	 */
	public function getTimeoutCount(): int
	{
		return $this->_getStat('timeout');
	}

	/**
	 * @throws PropertyNotFoundException
	 */
	public function getFailureCount(): int
	{
		return $this->_getStat('failure');
	}

	/**
	 * @throws PropertyNotFoundException
	 */
	public function getTypeUnsupportedCount(): int
	{
		return $this->_getStat('type-unsupported');
	}
}
