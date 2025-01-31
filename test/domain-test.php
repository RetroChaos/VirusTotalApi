<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotalApi\Analysers\DomainAnalyser;
use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

//Password optional
$response = $virusTotal->scanDomain('google.com');

if ($response['success']) {
	try {
		$analyser = new DomainAnalyser($response);
		echo $analyser->isDomainSafe() ? "Domain is safe!\n" : "Domain is malicious!\n";
		echo $analyser->getLastAnalysisDate() . "\n";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage();
	}
} else {
	echo $response['message'];
}