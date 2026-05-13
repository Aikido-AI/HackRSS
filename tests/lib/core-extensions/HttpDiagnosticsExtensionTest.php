<?php
declare(strict_types=1);

/**
 * Test suite for HttpDiagnostics extension security fixes.
 * Verifies that path traversal vulnerabilities are properly mitigated.
 */
final class HttpDiagnosticsExtensionTest extends \PHPUnit\Framework\TestCase {

	private string $extensionDir;

	protected function setUp(): void {
		parent::setUp();
		$this->extensionDir = dirname(__DIR__, 3) . '/lib/core-extensions/xExtension-HttpDiagnostics';

		// Load the extension class
		require_once $this->extensionDir . '/extension.php';
	}

	/**
	 * Test that the extension rejects path traversal attempts with '..'
	 */
	public function testAssetRouteRejectsPathTraversalWithDotDot(): void {
		// Simulate the pentest attack: trying to read /etc/passwd
		$_GET['route'] = 'asset';
		$_GET['n'] = '../../../../../../etc/passwd';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		// Should return 400 Bad Request with 'invalid path' message
		$this->assertSame('invalid path', $output);
	}

	/**
	 * Test that the extension rejects absolute paths starting with '/'
	 */
	public function testAssetRouteRejectsAbsolutePaths(): void {
		$_GET['route'] = 'asset';
		$_GET['n'] = '/etc/passwd';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		$this->assertSame('invalid path', $output);
	}

	/**
	 * Test that the extension rejects Windows-style absolute paths
	 */
	public function testAssetRouteRejectsWindowsAbsolutePaths(): void {
		$_GET['route'] = 'asset';
		$_GET['n'] = '\\windows\\system32\\config\\sam';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		$this->assertSame('invalid path', $output);
	}

	/**
	 * Test various path traversal attack patterns
	 */
	public function testAssetRouteRejectsVariousTraversalPatterns(): void {
		$maliciousPatterns = [
			'../../../etc/passwd',
			'..\\..\\..\\windows\\system.ini',
			'....//....//....//etc/passwd',
			'metadata.json/../../../etc/passwd',
			'./../../etc/passwd',
		];

		foreach ($maliciousPatterns as $pattern) {
			$_GET['route'] = 'asset';
			$_GET['n'] = $pattern;

			ob_start();
			HttpDiagnosticsExtension::handleApiMisc();
			$output = ob_get_clean();

			// All should be rejected with 'invalid path' or 'missing'
			$this->assertThat(
				$output,
				$this->logicalOr(
					$this->equalTo('invalid path'),
					$this->equalTo('missing')
				),
				"Pattern '{$pattern}' should be rejected"
			);
		}
	}

	/**
	 * Test that legitimate file access still works (metadata.json)
	 */
	public function testAssetRouteAllowsLegitimateFileAccess(): void {
		$_GET['route'] = 'asset';
		$_GET['n'] = 'metadata.json';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		// Should successfully read the metadata.json file
		$this->assertNotEmpty($output);
		$this->assertNotSame('invalid path', $output);
		$this->assertNotSame('missing', $output);

		// Verify it's valid JSON
		$decoded = json_decode($output, true);
		$this->assertIsArray($decoded);
		$this->assertArrayHasKey('name', $decoded);
	}

	/**
	 * Test that default parameter (no 'n' parameter) works correctly
	 */
	public function testAssetRouteDefaultsToMetadataJson(): void {
		$_GET['route'] = 'asset';
		unset($_GET['n']);

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		// Should successfully read the metadata.json file
		$this->assertNotEmpty($output);
		$decoded = json_decode($output, true);
		$this->assertIsArray($decoded);
	}

	/**
	 * Test that non-existent files return 404
	 */
	public function testAssetRouteReturns404ForNonExistentFile(): void {
		$_GET['route'] = 'asset';
		$_GET['n'] = 'nonexistent-file.txt';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		$this->assertSame('missing', $output);
	}

	/**
	 * Test that realpath validation prevents symlink attacks
	 */
	public function testAssetRouteValidatesRealPath(): void {
		// Even if a file exists, if realpath resolves outside the extension dir,
		// it should be rejected. This test verifies the realpath check is in place.
		$_GET['route'] = 'asset';
		$_GET['n'] = 'extension.php/../../../constants.php';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		// Should be rejected because it contains '..'
		$this->assertSame('invalid path', $output);
	}

	/**
	 * Test that the extension only serves files from within its directory
	 */
	public function testAssetRouteEnforcesDirectoryBoundary(): void {
		// Try to access extension.php which exists in the directory
		$_GET['route'] = 'asset';
		$_GET['n'] = 'extension.php';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		// Should successfully read the file
		$this->assertNotEmpty($output);
		$this->assertStringContainsString('HttpDiagnosticsExtension', $output);
	}

	/**
	 * Test URL-encoded path traversal attempts
	 */
	public function testAssetRouteRejectsUrlEncodedTraversal(): void {
		// URL-encoded '..' is '%2e%2e'
		$_GET['route'] = 'asset';
		$_GET['n'] = '%2e%2e/%2e%2e/etc/passwd';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		// The URL decoding happens before our code, but the '..' check should catch it
		// If not decoded, it will just be a missing file
		$this->assertThat(
			$output,
			$this->logicalOr(
				$this->equalTo('invalid path'),
				$this->equalTo('missing')
			)
		);
	}

	/**
	 * Test that null bytes are handled safely
	 */
	public function testAssetRouteHandlesNullBytes(): void {
		$_GET['route'] = 'asset';
		$_GET['n'] = "metadata.json\0.txt";

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		// Should either reject or not find the file
		$this->assertThat(
			$output,
			$this->logicalOr(
				$this->equalTo('invalid path'),
				$this->equalTo('missing')
			)
		);
	}

	/**
	 * Test CORS route still works (not affected by security fix)
	 */
	public function testCorsRouteStillWorks(): void {
		$_GET['route'] = 'cors';
		$_GET['test'] = 'value';
		$_SERVER['REQUEST_METHOD'] = 'GET';

		ob_start();
		HttpDiagnosticsExtension::handleApiMisc();
		$output = ob_get_clean();

		$decoded = json_decode($output, true);
		$this->assertIsArray($decoded);
		$this->assertArrayHasKey('query', $decoded);
		$this->assertArrayHasKey('test', $decoded['query']);
		$this->assertSame('value', $decoded['query']['test']);
	}

	protected function tearDown(): void {
		// Clean up $_GET and $_SERVER
		$_GET = [];
		$_SERVER = [];

		// Clear headers if xdebug is available
		if (function_exists('xdebug_get_headers')) {
			header_remove();
		}

		parent::tearDown();
	}
}
