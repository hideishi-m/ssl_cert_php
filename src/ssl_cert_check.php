<?php

new SSLCertificateCheck();

class SSLCertificateCheck
{
	private array $json = [
		'result' => [
			'value' => 'invalid',
			'message' => '',
		],
		'x509' => [
			'version' => null,
			'serial_number' => null,
			'signature_algorithm' => null,
			'issuer' => null,
			'not_before' => [
				'timestamp' => 0,
			],
			'not_after' => [
				'timestamp' => 0,
			],
			'subject' => null,
			'alternative_names' => null,
			'public_key_algorithm' => null,
		],
		'sha1_fingerprint' => null,
	];

	private function match_in_line(string $needle, string $text): string
	{
		$output = '';
		$regex = '#^\s*' . preg_quote($needle, '#') . ': (.+)$#m';
		if (preg_match($regex, $text, $match)) {
			$output = $match[1];
		}
		return $output;
	}

	private function match_next_line(string $needle, string $text): string
	{
		$output = '';
		$regex = '#^\s*' . preg_quote($needle, '#') . ':\s+(.+)$#m';
		if (preg_match($regex, $text, $match)) {
			$output = $match[1];
		}
		return $output;
	}

	private function filterVersion(string $output): int
	{
		if ('' !== $output
			&& preg_match('#^(\d+)#', $output, $match)) {
			$output = $match[1];
		}
		return intval($output);
	}

	private function filterTimestamp(string $output): int
	{
		if ('' !== $output) {
			return (new DateTimeImmutable($output))->getTimestamp();
		} else {
			return 0;
		}
	}

	private function validateCertificate(string $certPath): void
	{
		if (empty($certPath)) {
			$this->json['result']['message'] = 'Certificate file is not specified';
			return;
		} elseif (! is_file($certPath)) {
			$this->json['result']['message'] = 'Certificate file does not exist';
			return;
		} elseif (! is_readable($certPath)) {
			$this->json['result']['message'] = 'Certificate file is not readable';
			return;
		}

		$pem = file_get_contents($certPath);
		if (false === openssl_x509_export($pem, $text, FALSE)) {
			$this->json['result']['message'] = 'Certificate file is not valid';
			return;
		}

		$this->json['x509']['version'] = $this->filterVersion($this->match_in_line('Version', $text));
		$this->json['x509']['serial_number'] = $this->match_next_line('Serial Number', $text);
		$this->json['x509']['signature_algorithm'] = $this->match_in_line('Signature Algorithm', $text);
		$this->json['x509']['issuer'] = $this->match_in_line('Issuer', $text);
		$this->json['x509']['not_before']['timestamp'] = $this->filterTimestamp($this->match_in_line('Not Before', $text));
		$this->json['x509']['not_after']['timestamp'] = $this->filterTimestamp($this->match_in_line('Not After ', $text));
		$this->json['x509']['subject'] = $this->match_in_line('Subject', $text);
		$this->json['x509']['alternative_names'] = $this->match_next_line('X509v3 Subject Alternative Name', $text);
		$this->json['x509']['public_key_algorithm'] = $this->match_in_line('Public Key Algorithm', $text);
		$this->json['sha1_fingerprint'] = preg_replace('#(..)(?=..)#', '$1:', openssl_x509_fingerprint($pem, 'sha1'));

		$now = time();
		if ($this->json['x509']['not_before']['timestamp'] < $now
			&& $now < $this->json['x509']['not_after']['timestamp']) {
			if ($this->json['x509']['issuer'] === $this->json['x509']['subject']) {
				$this->json['result']['value'] = 'valid-but-self-signed';
			} else {
				$this->json['result']['value'] = 'valid';
			}
		}
	}

	public function __construct()
	{
		global $argv;
		$certPath = $argv[1] ?? '';
		$this->validateCertificate($certPath);
		echo json_encode($this->json);
	}
}
