<?php

namespace RetroChaos\VirusTotalApi\Analyser;

use Carbon\Carbon;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Response\DomainResponse;

class DomainAnalyser extends BaseAnalyser
{
	/**
	 * Only accepts DomainResponse to avoid passing in any array.
	 * @param DomainResponse $report
	 */
	public function __construct(DomainResponse $report)
	{
		$this->_report = $report->getRawData();
	}

	/**
	 * In case you need to change the report response but don't necessarily want to create a new analyser object.
	 * @param DomainResponse $report
	 * @return $this
	 */
	public function setReport(DomainResponse $report): self
	{
		$this->_report = $report->getRawData();
		return $this;
	}

	/**
	 * Returns true if both malicious count and suspicious count is zero.
	 * @return bool
	 */
	public function isDomainSafe(): bool
	{
		try {
			return $this->getMaliciousCount() === 0 && $this->getSuspiciousCount() === 0;
		} catch (PropertyNotFoundException $e) {
			return false;
		}
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
	public function getLastHttpsCertificateDate(): string
	{
		return Carbon::createFromTimestamp($this->_getAttribute('last_https_certificate_date'), 'UTC')->toDateTimeString();
	}

	/**
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getLastDnsRecordsDate(): string
	{
		return Carbon::createFromTimestamp($this->_getAttribute('last_dns_records_date'), 'UTC')->toDateTimeString();
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
	 * @throws PropertyNotFoundException
	 * @return string
	 */
	public function getTld(): string
	{
		return $this->_getAttribute('tld');
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
	public function getLastDnsRecords(): array
	{
		return $this->_getAttribute('last_dns_records');
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
	public function getWhoisDate(): string
	{
		return Carbon::createFromTimestamp($this->_getAttribute('last_modification_date'), 'UTC')->toDateTimeString();
	}
}
