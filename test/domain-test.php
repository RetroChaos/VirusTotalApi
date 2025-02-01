<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotalApi\Analysers\DomainAnalyser;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

$response = $virusTotal->scanDomain('google.com');

if ($response->isSuccessful()) {
	try {
		$analyser = new DomainAnalyser($response);
		echo $analyser->isDomainSafe() ? "Domain is safe!\n" : "Domain is malicious!\n";
		echo $analyser->getLastAnalysisDate() . "\n";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage();
	}
} else {
	echo $response->getErrorMessage();
}