<?php

namespace RetroChaos\VirusTotalApi\Analysers;

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;

class FileAnalyser extends BaseAnalyser
{
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
