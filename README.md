# VirusTotal API

A PHP library for accessing the [VirusTotal API](https://docs.virustotal.com/reference/overview).

Based off of work done by [IzzySoft](https://github.com/IzzySoft/virustotal/) and [jayzeng](https://github.com/jayzeng/virustotal_apiwrapper/).

Uses Guzzle6 or Guzzle7

## Install

Install using [composer](https://getcomposer.org/)

```sh
composer install retrochaos/virustotal-api
```

## Usage

Example script modified from ```test/file-test.php```

```php
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
```

Another example is testing IP addresses:
(Example script modified from ```test/ip-test.php```)

```php
use RetroChaos\VirusTotalApi\Analysers\IpAddressAnalyser;
use RetroChaos\VirusTotalApi\Exceptions\PropertyNotFoundException;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

//Password optional
$response = $virusTotal->scanIpAddress('8.8.8.8');

if ($response['success']) {
	try {
		$analyser = new IpAddressAnalyser($response);
		echo $analyser->isIpAddressSafe() ? "IP address is safe!\n" : "IP address is malicious!\n";
		echo $analyser->getLastAnalysisDate() . "\n";
	} catch (PropertyNotFoundException $e) {
		echo $e->getMessage();
	}
} else {
	echo $response['message'];
}
```

## TODO

- Add other methods found in the API.
- Bulk out FileAnalyser.
- POST file data to the endpoint, not just filesystem paths.
