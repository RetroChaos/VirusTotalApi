<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

//Password optional
$response = $virusTotal->scanFile('/path/to/file.zip');

if ($response['success']) {
	try {
		// We can get the analysis ID from the response of the file scan,
		// otherwise you can always manually enter an ID to get the report.
		$id = $virusTotal->getAnalysisId($response);
		$report = $virusTotal->getFileReport($id);
		echo $virusTotal->isFileSafe($report) ? "File is safe!" : "File is malicious!";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage();
	}
} else {
	echo $response['message'];
}