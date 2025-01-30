<?php

namespace RetroChaos\VirusTotalApi;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class HttpClient
{
	/**
	 * @var string $_apiKey
	 */
	private string $_apiKey;

	/**
	 * @var Client $_client
	 */
	private Client $_client;

	/**
	 * A wrapper for the main Guzzle Client.
	 * @param string $apiKey
	 */
	public function __construct(string $apiKey)
	{
		$this->_apiKey = $apiKey;
		$this->_client = new Client(['base_uri' => 'https://www.virustotal.com/api/v3/']);
	}

	/**
	 * Makes a Guzzle request while handling errors
	 * @param string $method
	 * @param string $url
	 * @param array $options
	 * @return array
	 */
	public function request(string $method, string $url, array $options = []): array
	{
		$options['headers'] = [
			'accept' => 'application/json',
			'x-apikey' => $this->_apiKey,
		];
		try {
			$response = $this->_client->request($method, $url, $options);
			$return = json_decode($response->getBody()->getContents(), true);
			$return['statusCode'] = $response->getStatusCode();
			$return['success'] = true;
			$return['message'] = '';
			return $return;
		} catch (GuzzleException $e) {
			return [
				'success' => false,
				'message' => $e->getMessage(),
			];
		}
	}
}
