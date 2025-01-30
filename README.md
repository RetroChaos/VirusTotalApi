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

Example script modified from ```test/debug.php```

```php
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
```

## TODO

- Add other methods found in the API
- POST file data to the endpoint, not just filesystem paths.
