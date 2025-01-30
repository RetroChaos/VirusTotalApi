# VirusTotal API

A PHP library for accessing the [VirusTotal API](https://docs.virustotal.com/reference/overview).

Based off of work done by [IzzySoft](https://github.com/IzzySoft/virustotal/) and [jayzeng](https://github.com/jayzeng/virustotal_apiwrapper/).

Requires Guzzle7

## Install

TODO: Setup a packagist repository.

Install using [composer](https://getcomposer.org/)

## Usage

Example script modified from ```test/debug.php```

```php
use RetroChaos\VirusTotal;

// Replace with your actual API Key.
$virusTotal = new VirusTotal('your-api-key');

//Password is optional for password-protected zip files.
$result = $virusTotal->filePathScan('/path/to/file');

//Boolean returned.
return $virusTotal->isFileSafe($result);
```

## TODO

- Create a packagist repository so this can be installed as a composer dependency.
- Add other methods found in the API
- POST file data to the endpoint, not just filesystem paths.
