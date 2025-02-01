<?php

namespace RetroChaos\VirusTotalApi\Api;

use RetroChaos\VirusTotalApi\Response\IpAddressResponse;

class IpApi extends BaseApi
{
	public function getIpReport(string $ipAddress): IpAddressResponse
	{
		$response = $this->_httpClient->request('GET', "ip_addresses/$ipAddress");
		if ($response['success']) {
			return new IpAddressResponse($response['data'], $response['status_code']);
		} else {
			return new IpAddressResponse(null, $response['status_code'], false, $response['error_message'], $response['exception']);
		}
	}

	public function voteIp(string $ipAddress, bool $isMalicious): void
	{
		$this->_httpClient->request('POST', "ip_addresses/$ipAddress/votes", [
			"body" => json_encode($isMalicious ? self::MALICIOUS_VOTE_BODY : self::HARMLESS_VOTE_BODY),
			"headers" => ['Content-Type' => 'application/json'],
		]);
	}
}