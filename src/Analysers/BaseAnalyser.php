<?php

namespace RetroChaos\VirusTotalApi\Analysers;

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;

class BaseAnalyser
{
	/**
	 * @var array $_report
	 */
	protected array $_report;

	/**
	 * @param string $key
	 * @return int|string|array
	 * @throws PropertyNotFoundException
	 */
	protected function _getAttribute(string $key)
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
	protected function _getVotes(string $key): int
	{
		if (!isset($this->_report['data']['attributes']['total_votes'][$key])) {
			throw new PropertyNotFoundException("$key not found in the report!");
		}

		return $this->_report['data']['attributes']['total_votes'][$key];
	}

	/**
	 * @param string $key
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	protected function _getLastAnalysisStat(string $key): int
	{
		if (!isset($this->_report['data']['attributes']['last_analysis_stats'][$key])) {
			throw new PropertyNotFoundException("$key count not found in the report!");
		}

		return $this->_report['data']['attributes']['last_analysis_stats'][$key];
	}

	/**
	 * @param string $key
	 * @return int
	 * @throws PropertyNotFoundException
	 */
	protected function _getStat(string $key): int
	{
		if (!isset($this->_report['data']['attributes']['stats'][$key])) {
			throw new PropertyNotFoundException("$key count not found in the report!");
		}
		return $this->_report['data']['attributes']['stats'][$key];
	}

	/**
	 * @param string $key
	 * @return string
	 * @throws PropertyNotFoundException
	 */
	protected function _getFileInfo(string $key): string
	{
		if (!isset($this->_report['meta']['file_info'][$key])) {
			throw new PropertyNotFoundException("$key count not found in the report!");
		}
		return $this->_report['meta']['file_info'][$key];
	}
}
