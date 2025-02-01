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

1. Firstly you need to instantiate a HttpClient object with your API key from VirusTotal (you can obtain one from creating an account for free).
2. Then you create a new Service object with the HttpClient. This is the main object where requests are made, such as scanning files, domains and IPs.
3. The Service object will return back a Response object of that type eg. if you're calling: ```$service->scanDomain()``` a ```DomainResponse``` object will be returned. You can always call the ```getRawResponse()``` method on the object to get an associative array returned from Guzzle
4. To aid with your code, each response comes with a dedicated Analyser class to call specific methods on the response that was returned. Eg. a DomainAnalyser object requires a DomainResponse object.

To recap:
HttpClient -> Service -> Response -> Analyser

Example script modified from ```test/file-test.php```

```php
use RetroChaos\VirusTotalApi\Analyser\FileAnalyser;
use RetroChaos\VirusTotalApi\HttpClient;
use RetroChaos\VirusTotalApi\Service;

$httpClient = new HttpClient('your-api-key');
$virusTotal = new Service($httpClient);

//Password optional
$response = $virusTotal->scanFileUntilCompleted('/path/to/file.zip');

if ($response->isSuccessful()) {
	$analyser = new FileAnalyser($response);
	echo $analyser->isFileSafe() ? "File is safe!\n" : "File is malicious!\n";
} else {
	echo $response->getErrorMessage();
}
```

Another example is testing IP addresses:
(Example script modified from ```test/ip-test.php```)

```php
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
```

## TODO

- Add other methods found in the API.
- Bulk out FileAnalyser.
- POST file data to the endpoint, not just filesystem paths.
