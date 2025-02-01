<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotalApi\Analyser\IpAddressAnalyser;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

$response = $virusTotal->scanIpAddress('8.8.8.8');

if ($response->isSuccessful()) {
	try {
		$analyser = new IpAddressAnalyser($response);
		echo $analyser->isIpAddressSafe() ? "IP address is safe!\n" : "IP address is malicious!\n";
		echo $analyser->getLastAnalysisDate() . "\n";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage();
	}
} else {
	echo $response->getErrorMessage();
}