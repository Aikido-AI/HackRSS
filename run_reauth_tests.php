#!/usr/bin/env php
<?php
declare(strict_types=1);

// Simple test runner for our reauthentication tests
require __DIR__ . '/tests/bootstrap.php';

// Manually run the test class
$testClass = 'configureControllerReauthTest';
$testFile = __DIR__ . '/tests/app/Controllers/configureControllerReauthTest.php';

if (!file_exists($testFile)) {
	echo "Test file not found: $testFile\n";
	exit(1);
}

require_once $testFile;

if (!class_exists($testClass)) {
	echo "Test class not found: $testClass\n";
	exit(1);
}

echo "PHPUnit-style Test Runner\n";
echo "==========================\n\n";
echo "Running tests from $testClass...\n\n";

$reflection = new ReflectionClass($testClass);
$instance = $reflection->newInstance();
$methods = $reflection->getMethods(ReflectionMethod::IS_PUBLIC);

$passed = 0;
$failed = 0;
$errors = [];
$testResults = [];

foreach ($methods as $method) {
	$methodName = $method->getName();
	
	// Skip non-test methods
	if (!str_starts_with($methodName, 'test')) {
		continue;
	}
	
	$startTime = microtime(true);
	
	try {
		// Call setUp if it exists
		if ($reflection->hasMethod('setUp')) {
			$instance->setUp();
		}
		
		// Run the test
		$method->invoke($instance);
		
		// Call tearDown if it exists
		if ($reflection->hasMethod('tearDown')) {
			$instance->tearDown();
		}
		
		$duration = (microtime(true) - $startTime) * 1000;
		echo ".";
		$passed++;
		$testResults[] = [
			'name' => $methodName,
			'passed' => true,
			'duration' => $duration,
		];
	} catch (Throwable $e) {
		$duration = (microtime(true) - $startTime) * 1000;
		echo "F";
		$failed++;
		$errors[] = [
			'method' => $methodName,
			'error' => $e->getMessage(),
			'trace' => $e->getTraceAsString(),
		];
		$testResults[] = [
			'name' => $methodName,
			'passed' => false,
			'duration' => $duration,
		];
	}
}

echo "\n\n";
echo "Time: " . number_format(array_sum(array_column($testResults, 'duration')), 2) . " ms\n";
echo "Tests: " . ($passed + $failed) . ", Assertions: " . ($passed + $failed) . ", ";

if ($failed > 0) {
	echo "Failures: $failed\n";
	echo "\nFAILURES!\n";
	foreach ($errors as $i => $error) {
		echo "\n" . ($i + 1) . ") {$testClass}::{$error['method']}\n";
		echo "{$error['error']}\n\n";
	}
	exit(1);
} else {
	echo "Passed: $passed\n";
	echo "\nOK ($passed tests)\n";
}

exit(0);
