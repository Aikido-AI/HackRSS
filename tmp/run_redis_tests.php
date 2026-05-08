#!/usr/bin/env php
<?php
/**
 * Simple test runner for Redis security tests
 * This script runs the Redis security tests and outputs results
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

const COPY_LOG_TO_SYSLOG = false;

// Load FreshRSS
require __DIR__ . '/../constants.php';
require LIB_PATH . '/lib_rss.php';

// Check if PHPUnit is available
if (!class_exists('PHPUnit\Framework\TestCase')) {
	echo "PHPUnit not available. Attempting to load from vendor...\n";
	if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
		require __DIR__ . '/../vendor/autoload.php';
	} else {
		echo "ERROR: PHPUnit not found. Please run 'composer install'\n";
		exit(1);
	}
}

// Load the test file
require __DIR__ . '/../tests/lib/SimplePie/Cache/RedisSecurityTest.php';

// Run tests manually
echo "Running Redis Security Tests...\n";
echo str_repeat("=", 80) . "\n";

$testClass = new RedisSecurityTest('test');
$reflection = new ReflectionClass($testClass);
$methods = $reflection->getMethods(ReflectionMethod::IS_PUBLIC);

$passed = 0;
$failed = 0;
$skipped = 0;

foreach ($methods as $method) {
	if (strpos($method->getName(), 'test') === 0) {
		$testName = $method->getName();
		echo "\n{$testName}: ";
		
		try {
			$testClass->setUp();
			$method->invoke($testClass);
			$testClass->tearDown();
			echo "✓ PASSED\n";
			$passed++;
		} catch (Exception $e) {
			if (strpos($e->getMessage(), 'skipped') !== false || strpos($e->getMessage(), 'Skip') !== false) {
				echo "⊘ SKIPPED: " . $e->getMessage() . "\n";
				$skipped++;
			} else {
				echo "✗ FAILED: " . $e->getMessage() . "\n";
				$failed++;
			}
		}
	}
}

echo "\n" . str_repeat("=", 80) . "\n";
echo "Results: {$passed} passed, {$failed} failed, {$skipped} skipped\n";

exit($failed > 0 ? 1 : 0);
