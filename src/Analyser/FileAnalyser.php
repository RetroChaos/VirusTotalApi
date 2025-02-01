<?php

namespace RetroChaos\VirusTotalApi\Analyser;

use Carbon\Carbon;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Response\FileReportResponse;

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
	 * @return self
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
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getMaliciousCount(): int
	{
		return $this->_getStat('malicious');
	}

	/**
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getSuspiciousCount(): int
	{
		return $this->_getStat('suspicious');
	}

	/**
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getUndetectedCount(): int
	{
		return $this->_getStat('undetected');
	}

	/**
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getHarmlessCount(): int
	{
		return $this->_getStat('harmless');
	}

	/**
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getTimeoutCount(): int
	{
		return $this->_getStat('timeout');
	}

	/**
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getFailureCount(): int
	{
		return $this->_getStat('failure');
	}

	/**
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	public function getTypeUnsupportedCount(): int
	{
		return $this->_getStat('type-unsupported');
	}

	/**
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getSha256(): string
	{
		return $this->_getFileInfo('sha256');
	}

	/**
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getMd5(): string
	{
		return $this->_getFileInfo('md5');
	}

	/**
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getSha1(): string
	{
		return $this->_getFileInfo('sha1');
	}

	/**
	 * Returns the filesize in Megabytes.
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getFileSize(): string
	{
		return number_format(($this->_getFileInfo('size') / (1024 ** 2)), 2);
	}

	/**
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getStatus(): string
	{
		return $this->_getAttribute('status');
	}

	/**
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getDate(): string
	{
		return Carbon::createFromTimestamp($this->_getAttribute('date'), 'UTC')->toDateTimeString();
	}

	/**
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	public function getFileId(): string
	{
		return $this->_getAttribute('id');
	}
}
