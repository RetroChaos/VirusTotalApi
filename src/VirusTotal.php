<?php

namespace RetroChaos;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;

class VirusTotal
{
	const BASE_URL = 'https://www.virustotal.com/api/v3/';

	/**
	 * @var string $_apiKey
	 */
	private string $_apiKey;

	public function __construct(string $apiKey)
	{
		$this->_apiKey = $apiKey;
	}

	private function _headers(): array
	{
		return [
			'accept' => 'application/json',
			'x-apikey' => $this->_apiKey,
		];
	}

	private function _makeRequest(string $baseUrl, string $urlPath, string $method, array $params): array
	{
		try {
			$client = new GuzzleClient([
				'base_uri' => $baseUrl,
			]);
			$response = $client->request($method, $urlPath, $params);
			return json_decode($response->getBody()->getContents(), true);
		} catch (GuzzleException $e) {
			$return['success'] = false;
			$return['message'] = 'GuzzleException: ' . $e->getMessage();
			return $return;
		}
	}

	public function filePathScan(string $path, string $password = null): array
	{
		$return = [];
		$baseUrl = self::BASE_URL;
		$urlPath = 'files';

		$filesize = filesize($path)/(1024^2);
		if ($filesize > 200) {
			$filesizeString = number_format($filesize, 2) . "MB";
			$return['success'] = false;
			$return['message'] = "File size too large. Please upload a smaller file, under 200MB. Your current filesize is $filesizeString.";
			return $return;
		}
		if ($filesize >= 32) {
			$json = $this->_makeRequest($baseUrl, 'files/upload_url', 'GET', [
				'headers' => $this->_headers(),
			]);
			if (isset($json['success']) && $json['success'] === false) {
				return $json;
			}
			$url = $json['data'];
			$parsedUrl = parse_url($url);
			$baseUrl = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . '/';
			$urlPath = ltrim($parsedUrl['path'], '/');
		}

		$multipart = [
			[
				'name' => 'file',
				'filename' => basename($path),
				'contents' => fopen($path, 'r'),
				'headers' => [
					'Content-Type' => mime_content_type($path) ?: 'application/octet-stream',
				]
			]
		];

		if (null !== $password) {
			$multipart[] = [
				'name' => 'password',
				'contents' => $password,
			];
		}

		$json = $this->_makeRequest($baseUrl, $urlPath, 'POST', [
			'multipart' => $multipart,
			'headers' => $this->_headers(),
		]);
		if (isset($json['success']) && $json['success'] === false) {
			return $json;
		}
		return $this->getFileReport($json['data']['id']);
	}

	public function getFileReport(string $analysisId): array
	{
		return $this->_makeRequest(self::BASE_URL, "analyses/$analysisId", 'GET', [
			'headers' => $this->_headers(),
		]);
	}

	public function isFileSafe(array $output): bool
	{
		if (empty($output) ||
			$output['data']['attributes']['stats']['malicious'] > 0 ||
			$output['data']['attributes']['stats']['suspicious'] > 0
		) {
			return false;
		} else {
			return true;
		}
	}
}