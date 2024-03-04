<?php

new SSLCertificatesDiscovery();

class SSLCertificatesDiscovery
{
	private array $certPaths = [];
	private array $json = [];
	
	private function getDefaultConfDir(): string
	{
		if ('FreeBSD' === PHP_OS) {
			return '/usr/local/etc/nginx/conf.d';
		} elseif ('Linux' === PHP_OS) {
			return '/etc/nginx/conf.d';
		} else {
			return getenv('HOME');
		}
	}

	private function findNginxConfDir(string $confDir, array &$certPaths): void
	{
		if (! preg_match('#/$#', $confDir)) {
			$confDir .= '/';
		}
		if (is_dir($confDir)
			&& is_readable($confDir)) {
			$dh = opendir($confDir);
			if ($dh) {
				while (false !== ($entry = readdir($dh))) {
					if ('.' === $entry || '..' === $entry) {
						continue;
					}
					$path = "{$confDir}{$entry}";
					if (is_dir($path)) {
						$this->findNginxConfDir($path, $certPaths);
					} elseif (preg_match('#^[^\.]+\.conf$#', $entry)) {
						$this->parseNginxConfFile($path, $certPaths);
					}
				}
				closedir($dh);
			}
		}
	}

	private function parseNginxConfFile(string $path, array &$certPaths): void
	{
		$fp = fopen($path, 'r');
		if ($fp) {
			while (false !== ($buffer = fgets($fp))) {
				if (preg_match('/^[^#]*ssl_certificate\s+([^ #;]+)\s*;\s*(?:#.*)?$/', $buffer, $match)) {
					$certPath = $match[1];
					if (! in_array($certPath, $certPaths, true)
						&& is_file($certPath)) {
						$certPaths[] = $certPath;
					}
				}
			}
			fclose($fp);
		}
	}

	private function discoverCertificates(string $path): void
	{
		$certPaths = [];
		$this->findNginxConfDir($path, $certPaths);

		foreach ($certPaths as $certPath) {
			if (is_readable($certPath)
				&& false !== ($pem = file_get_contents($certPath))
				&& false !== ($cert = openssl_x509_parse($pem))) {
				if (isset($cert['subject'])
					&& isset($cert['subject']['CN'])) {
					$this->json[] = [
						'{#CERTNAME}' => $cert['subject']['CN'],
						'{#CERTPATH}' => $certPath,
					];
				}
			}
		}
	}

	public function __construct()
	{
		global $argv;
		$confDir = $argv[1] ?? '';
		$this->discoverCertificates($confDir ?: $this->getDefaultConfDir());
		echo json_encode($this->json);
	}
}
