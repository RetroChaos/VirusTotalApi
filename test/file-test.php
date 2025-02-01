<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotalApi\Analyser\FileAnalyser;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

//Password optional
$response = $virusTotal->scanFileUntilCompleted('/path/to/file.zip');

if ($response->isSuccessful()) {
	$analyser = new FileAnalyser($response);
	echo $analyser->isFileSafe() ? "File is safe!\n" : "File is malicious!\n";
	try {
		echo $analyser->getFileSize() . "MB\n";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage();
	}
} else {
	echo $response->getErrorMessage();
}