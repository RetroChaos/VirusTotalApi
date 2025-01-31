<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotalApi\Analysers\FileAnalyser;
use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

//Password optional
$response = $virusTotal->scanFile('/path/to/file.zip');

if ($response->isSuccessful()) {
	$analyser = new FileAnalyser($response);
	echo $analyser->isFileSafe() ? "File is safe!\n" : "File is malicious!\n";
} else {
	echo $response->getErrorMessage();
}