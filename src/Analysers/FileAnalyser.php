<?php

namespace RetroChaos\VirusTotalApi\Analysers;

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;

class FileAnalyser
{
	/**
	 * @var array $_report
	 */
	private array $_report;

	/**
	 * An object in which you can call aggregate data about the file scanned.
	 * @param array $report
	 */
	public function __construct(array $report)
	{
		$this->_report = $report;
	}

	/**
	 * In case you need to change the report response array but don't necessarily want to create a new analyser object.
	 * @param array $report
	 * @return $this
	 */
	public function setReport(array $report): self
	{
		$this->_report = $report;
		return $this;
	}

	/**
	 * Gets the stat of the report based on the key
	 * @param string $key
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	private function _getStat(string $key): int
	{
		if (!isset($this->_report['data']['attributes']['stats'][$key])) {
			throw new PropertyNotFoundException("$key count not found in the report!");
		}
		return $this->_report['data']['attributes']['stats'][$key];
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
