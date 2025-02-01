<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotalApi\Analyser\FileAnalyser;
use RetroChaos\VirusTotalApi\Exception\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

//Password optional
echo "Scanning until complete...\n";
$response = $virusTotal->scanFileUntilCompleted('/path/to/file.zip');

if ($response->isSuccessful()) {
	$analyser = new FileAnalyser($response);
	try {
		echo $analyser->getStatus() . "\n";
		echo $analyser->isFileSafe() ? "File is safe!\n" : "File is malicious!\n";
		echo $analyser->getFileSize() . "MB\n";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage() . "\n";
	}
} else {
	echo $response->getErrorMessage() . "\n";
}