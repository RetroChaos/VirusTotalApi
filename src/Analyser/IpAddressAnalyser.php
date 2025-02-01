<?php

namespace RetroChaos\VirusTotalApi\Analyser;

use Carbon\Carbon;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Response\IpAddressResponse;

class IpAddressAnalyser extends BaseAnalyser
{
	/**
	 * Only accepts IpAddressResponse to avoid passing in any array.
	 * @param IpAddressResponse $report
	 */
	public function __construct(IpAddressResponse $report)
	{
		$this->_report = $report->getRawResponse();
	}

	/**
	 * In case you need to change the report response but don't necessarily want to create a new analyser object.
	 * @param IpAddressResponse $report
	 * @return $this
	 */
	public function setReport(IpAddressResponse $report): self
	{
		$this->_report = $report->getRawResponse();
		return $this;
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
		return $this->_getLastAnalysisStat('malicious');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getSuspiciousCount(): int
	{
		return $this->_getLastAnalysisStat('suspicious');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getUndetectedCount(): int
	{
		return $this->_getLastAnalysisStat('undetected');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getHarmlessCount(): int
	{
		return $this->_getLastAnalysisStat('harmless');
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return int
	 */
	public function getTimeoutCount(): int
	{
		return $this->_getLastAnalysisStat('timeout');
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
	 * Returns an array of all the various scans and their results.
	 * @throws PropertyNotFoundException
	 * @return array
	 */
	public function getLastAnalysisResults(): array
	{
		return $this->_getAttribute('last_analysis_results');
	}
}