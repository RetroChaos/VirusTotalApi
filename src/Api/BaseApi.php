<?php

namespace RetroChaos\VirusTotalApi\Api;

use RetroChaos\VirusTotalApi\HttpClient;

class BaseApi
{
	const HARMLESS_VOTE_BODY = [
		"data" => [
			"type" => "vote",
			"attributes" => [
				"verdict" => "harmless"
			]
		]
	];

	const MALICIOUS_VOTE_BODY = [
		"data" => [
			"type" => "vote",
			"attributes" => [
				"verdict" => "malicious"
			]
		]
	];

	/**
	 * @var HttpClient $_httpClient
	 */
	protected HttpClient $_httpClient;

	/**
	 * @param HttpClient $httpClient
	 */
	public function __construct(HttpClient $httpClient)
	{
		$this->_httpClient = $httpClient;
	}
}