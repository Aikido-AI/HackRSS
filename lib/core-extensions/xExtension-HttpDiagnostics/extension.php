<?php
declare(strict_types=1);

/**
 * HttpDiagnostics — lightweight connectivity and HTTP diagnostics helpers.
 *
 * Exposes a small read-only API to help administrators understand why a feed
 * fails to subscribe: redirects, authentication walls, wrong content types, etc.
 *
 * API endpoint: `/api/misc.php/HttpDiagnostics/?route=<route>`
 */
final class HttpDiagnosticsExtension extends Minz_Extension {

	private const MAX_BODY_PREVIEW = 4096;

	#[\Override]
	public function init(): void {
		parent::init();

		$this->registerHook(Minz_HookType::ApiMisc, [self::class, 'handleApiMisc']);
	}

	public static function handleApiMisc(): void {
		$route = isset($_GET['route']) && is_string($_GET['route']) ? $_GET['route'] : 'ping';

		switch ($route) {
			case 'ping':
				self::jsonResponse(['ok' => true, 'time' => time()]);
				return;

			case 'connectivity':
				self::handleConnectivity();
				return;

			default:
				header('HTTP/1.1 404 Not Found');
				header('Content-Type: text/plain; charset=UTF-8');
				echo 'unknown route';
				return;
		}
	}

	/**
	 * Validate and sanitize a URL for connectivity checks.
	 * Implements domain allowlisting to prevent SSRF attacks.
	 *
	 * @param string $userUrl The user-provided URL to validate
	 * @return string The validated URL
	 * @throws Exception if the URL is invalid or not allowed
	 */
	private static function validateUrl(string $userUrl): string {
		try {
			// Basic URL validation
			$url = FreshRSS_http_Util::checkUrl($userUrl);
			if ($url === false || $url === '') {
				throw new Exception('Invalid URL');
			}

			// Parse the URL
			$parsedUrl = parse_url($url);
			if ($parsedUrl === false || !isset($parsedUrl['scheme']) || !isset($parsedUrl['host'])) {
				throw new Exception('Invalid URL');
			}

			// Validate protocol (only http and https allowed)
			$scheme = strtolower($parsedUrl['scheme']);
			if ($scheme !== 'http' && $scheme !== 'https') {
				throw new Exception('Invalid URL');
			}

			// Domain allowlist - SSRF protection
			const allowedDomains = ['example.com']; // add your allowed domains here
			$host = strtolower($parsedUrl['host']);

			// Check if the host matches any allowed domain (exact match only)
			$isAllowed = false;
			foreach (allowedDomains as $allowedDomain) {
				if ($host === strtolower($allowedDomain)) {
					$isAllowed = true;
					break;
				}
			}

			if (!$isAllowed) {
				throw new Exception('Invalid URL');
			}

			return $url;
		} catch (Exception $e) {
			throw new Exception('Invalid URL');
		}
	}

	/**
	 * Connectivity check: fetch a target URL and report the HTTP status, the
	 * final (post-redirect) URL, the response headers and a short body preview,
	 * so an admin can troubleshoot feeds that fail to subscribe.
	 */
	private static function handleConnectivity(): void {
		$target = isset($_GET['url']) && is_string($_GET['url']) ? trim($_GET['url']) : '';

		try {
			$url = self::validateUrl($target);
		} catch (Exception $e) {
			self::jsonResponse(['error' => 'invalid url'], 400);
			return;
		}

		$ch = curl_init();
		if ($ch === false) {
			self::jsonResponse(['error' => 'curl unavailable'], 500);
			return;
		}

		$responseHeaders = '';
		curl_setopt_array($ch, [
			CURLOPT_URL => $url,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_CONNECTTIMEOUT => 5,
			CURLOPT_TIMEOUT => 10,
			CURLOPT_USERAGENT => FRESHRSS_USERAGENT,
		]);
		curl_setopt($ch, CURLOPT_HEADERFUNCTION, static function ($ch, string $header) use (&$responseHeaders): int {
			$responseHeaders .= $header;
			return strlen($header);
		});

		$body = curl_exec($ch);
		$status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$effectiveUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
		$error = curl_error($ch);
		curl_close($ch);

		self::jsonResponse([
			'requested_url' => $url,
			'effective_url' => $effectiveUrl,
			'status' => $status,
			'headers' => trim($responseHeaders),
			'body_preview' => is_string($body) ? substr($body, 0, self::MAX_BODY_PREVIEW) : '',
			'error' => $error,
		]);
	}

	/** @param array<string,mixed> $data */
	private static function jsonResponse(array $data, int $status = 200): void {
		if ($status !== 200) {
			header('HTTP/1.1 ' . $status);
		}
		header('Content-Type: application/json; charset=UTF-8');
		header('Cache-Control: no-store');
		echo json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
	}
}
