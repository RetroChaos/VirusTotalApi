<?php

namespace RetroChaos\VirusTotalApi\Api;

use RetroChaos\VirusTotalApi\Response\DomainResponse;

class DomainApi extends BaseApi
{
	public function getDomainReport(string $domain): DomainResponse
	{
		$response = $this->_httpClient->request('GET', "domains/$domain");
		if ($response['success']) {
			return new DomainResponse($response['data'], $response['status_code']);
		} else {
			return new DomainResponse(null, $response['status_code'], false, $response['error_message'], $response['exception']);
		}
	}

	public function voteDomain(string $domain, bool $isMalicious): void
	{
		$this->_httpClient->request('POST', "domains/$domain/votes", [
			"body" => json_encode($isMalicious ? self::MALICIOUS_VOTE_BODY : self::HARMLESS_VOTE_BODY),
			"headers" => ['Content-Type' => 'application/json'],
		]);
	}
}