<?php

namespace RetroChaos\VirusTotalApi\Analysers;

use Carbon\Carbon;
use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;

class IpAddressAnalyser
{
	/**
	 * @var array $_report
	 */
	private array $_report;

	/**
	 * An object in which you can call aggregate data about the IP Address scanned.
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
	 * @param string $key
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	private function _getStat(string $key): int
	{
		if (!isset($this->_report['data']['attributes']['last_analysis_stats'][$key])) {
			throw new PropertyNotFoundException("$key count not found in the report!");
		}
		return $this->_report['data']['attributes']['last_analysis_stats'][$key];
	}

	/**
	 * @param string $key
	 * @return int|string|array
	 * @throws PropertyNotFoundException
	 */
	private function _getAttribute(string $key)
	{
		if (!isset($this->_report['data']['attributes'][$key])) {
			throw new PropertyNotFoundException("$key not found in the report!");
		}
		return $this->_report['data']['attributes'][$key];
	}

	/**
	 * @param string $key
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	private function _getVotes(string $key): int
	{
		if (!isset($this->_report['data']['attributes']['total_votes'][$key])) {
			throw new PropertyNotFoundException("$key not found in the report!");
		}
		return $this->_report['data']['attributes']['total_votes'][$key];
	}

	/**
	 * Returns true if both malicious count and suspicious count is zero.
	 * @return bool
	 */
	public function isIpAddressSafe(): bool
	{
		try {
			return $this->getMaliciousCount() === 0 && $this->getSuspiciousCount() === 0;
		} catch (PropertyNotFoundException $e) {
			return false;
		}
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getMaliciousCount(): int
	{
		return $this->_getStat('malicious');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getSuspiciousCount(): int
	{
		return $this->_getStat('suspicious');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getUndetectedCount(): int
	{
		return $this->_getStat('undetected');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getHarmlessCount(): int
	{
		return $this->_getStat('harmless');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getTimeoutCount(): int
	{
		return $this->_getStat('timeout');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getRegionalInternetRegistry(): string
	{
		return $this->_getAttribute('regional_internet_registry');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getCountry(): string
	{
		return $this->_getAttribute('country');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getContinent(): string
	{
		return $this->_getAttribute('continent');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getAsOwner(): string
	{
		return $this->_getAttribute('as_owner');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getWhoisDate(): string
	{
		return Carbon::createFromTimestamp($this->_getAttribute('whois_date'), 'UTC')->toDateTimeString();
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getLastAnalysisDate(): string
	{
		return Carbon::createFromTimestamp($this->_getAttribute('last_analysis_date'), 'UTC')->toDateTimeString();
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getLastModificationDate(): string
	{
		return Carbon::createFromTimestamp($this->_getAttribute('last_modification_date'), 'UTC')->toDateTimeString();
	}

	/**
	 * Returns a JSON string.
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getWhois(): string
	{
		return $this->_getAttribute('whois');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getReputation(): int
	{
		return $this->_getAttribute('reputation');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getNetwork(): string
	{
		return $this->_getAttribute('network');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getHarmlessVotes(): int
	{
		return $this->_getVotes('harmless');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getMaliciousVotes(): int
	{
		return $this->_getVotes('malicious');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return array
	 */
	public function getLastAnalysisResults(): array
	{
		return $this->_getAttribute('last_analysis_results');
	}
}