<?php

require 'vendor/autoload.php';

use RetroChaos\VirusTotal;

// Replace with your actual API Key
$virusTotal = new VirusTotal('your-api-key');

$testFile = tempnam(sys_get_temp_dir(), 'vttest');
file_put_contents($testFile, str_repeat('A', 100));

$result = $virusTotal->filePathScan($testFile);
unlink($testFile);
dd($virusTotal->isFileSafe($result));
