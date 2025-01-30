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

if ($response['success']) {
	try {
		// We can get the analysis ID from the response of the file scan,
		// otherwise you can always manually enter an ID to get the report.
		$id = $virusTotal->getFileAnalysisId($response);
		$report = $virusTotal->getFileReport($id);
		$analyser = new FileAnalyser($report);
		echo $analyser->isFileSafe() ? "File is safe!\n" : "File is malicious!\n";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage();
	}
} else {
	echo $response['message'];
}