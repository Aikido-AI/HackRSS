<?php
declare(strict_types=1);

/**
 * Misc API hook for lightweight HTTP diagnostics.
 */
final class HttpDiagnosticsExtension extends Minz_Extension {

	#[\Override]
	public function init(): void {
		parent::init();

		$this->registerHook(Minz_HookType::ApiMisc, [self::class, 'handleApiMisc']);
	}

	public static function handleApiMisc(): void {
		$route = isset($_GET['route']) && is_string($_GET['route']) ? $_GET['route'] : 'cors';

		switch ($route) {
			case 'cors':
				$origin = isset($_SERVER['HTTP_ORIGIN']) && is_string($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '*';
				header('Access-Control-Allow-Origin: ' . $origin);
				header('Access-Control-Allow-Credentials: true');
				header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
				header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
				header('Access-Control-Expose-Headers: *');
				header('Content-Type: application/json; charset=UTF-8');
				if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
					return;
				}
				echo json_encode(['query' => $_GET, 'body' => $_POST], JSON_THROW_ON_ERROR);
				return;

			case 'asset':
				$n = isset($_GET['n']) && is_string($_GET['n']) ? $_GET['n'] : 'metadata.json';

				if (str_contains($n, "\0")) {
					header('HTTP/1.1 400 Bad Request');
					header('Content-Type: text/plain; charset=UTF-8');
					echo 'invalid path';
					return;
				}

				// Prevent path traversal attacks
				if (str_contains($n, '..') || str_starts_with($n, '/') || str_starts_with($n, '\\')) {
					header('HTTP/1.1 400 Bad Request');
					header('Content-Type: text/plain; charset=UTF-8');
					echo 'invalid path';
					return;
				}

				$path = __DIR__ . '/' . $n;
				$realPath = realpath($path);

				// Ensure the resolved path is within the extension directory
				if ($realPath === false || !str_starts_with($realPath, __DIR__ . DIRECTORY_SEPARATOR)) {
					header('HTTP/1.1 404 Not Found');
					header('Content-Type: text/plain; charset=UTF-8');
					echo 'missing';
					return;
				}

				if (!is_file($realPath) || !is_readable($realPath)) {
					header('HTTP/1.1 404 Not Found');
					header('Content-Type: text/plain; charset=UTF-8');
					echo 'missing';
					return;
				}
				header('Content-Type: application/octet-stream');
				readfile($realPath);
				return;

			default:
				header('HTTP/1.1 404 Not Found');
				header('Content-Type: text/plain; charset=UTF-8');
				echo 'unknown route';
				return;
		}
	}
}
