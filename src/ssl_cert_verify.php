<?php

new SSLCertificateVerify();

class SSLCertificateVerify
{
	private int $time = 0;

	private array $json = [
		'result' => [
			'value' => 'invalid',
			'message' => '',
		],
		'chain' => [],
	];

	private function array_to_string(array $array): string
	{
		$result = [];
		foreach ($array as $key => $value) {
			if (is_array($value)) {
				$value = implode( "\n", $value);
			}
			$result[] = "{$key}={$value}";
		}
		return implode( ', ', $result);
	}

	private function pem_to_cert(string $pem): array
	{
		$x509 = openssl_x509_parse($pem);
		return [
			'subject' => $this->array_to_string($x509['subject']),
			'issuer' => $this->array_to_string($x509['issuer']),
			'not_before' => [
				'timestamp' => intval($x509['validFrom_time_t']),
			],
			'not_after' => [
				'timestamp' => intval($x509['validTo_time_t']),
			],
		];
	}

	private function cert_is_valid(array $cert): bool
	{
		return ($cert['not_before']['timestamp'] < $this->time && $this->time < $cert['not_after']['timestamp']);
	}

	private function pem_signed_by_issuer(string $pem, string $signed_pem): bool
	{
		$x509 = openssl_x509_parse($pem);
		$signed_x509 = openssl_x509_parse($signed_pem);
		return ($this->array_to_string($x509['issuer']) === $this->array_to_string($signed_x509['subject']));
	}

	private function loadCertificates(string $filePath): bool|array
	{
		if (empty($filePath)) {
			$this->json['result']['message'] = 'Certificate file is not specified';
			return false;
		} elseif (! is_file($filePath)) {
			$this->json['result']['message'] = 'Certificate file does not exist';
			return false;
		} elseif (! is_readable($filePath)) {
			$this->json['result']['message'] = 'Certificate file is not readable';
			return false;
		}

		$pem = file_get_contents($filePath);
		if (false === preg_match_all('#-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----#s', $pem, $matches)) {
			$this->json['result']['message'] = 'Certificate file is not valid';
			return false;
		}
		return $matches[0];
	}

	private function verifySignedCertificate(string $pem, string $signed_pem): bool
	{
		$result = [
			'x509' => null,
			'signed_x509' => null,
			'verify' => false,
		];

		$result['x509'] = $this->pem_to_cert($pem);
		if (false === $this->cert_is_valid($result['x509'])) {
			$this->json['result']['message'] = 'Certificate is expired';
			$this->json['chain'][] = $result;
			return false;
		}

		$result['signed_x509'] = $this->pem_to_cert($signed_pem);
		if (false === $this->cert_is_valid($result['signed_x509'])) {
			$this->json['result']['message'] = 'Signed certificate is expired';
			$this->json['chain'][] = $result;
			return false;
		}

		$signed_pkey = openssl_pkey_get_public($signed_pem);
		if (false === (1 === openssl_x509_verify($pem, $signed_pkey))) {
			$this->json['result']['message'] = 'Certificate is not signed with public key of signed certificate';
			$this->json['chain'][] = $result;
			return false;
		}

		$result['verify'] = true;
		$this->json['chain'][] = $result;
		return true;
	}

	private function verifyCertificateChain(string $certPath, string $rootCertPath): void
	{
		if (false === ($certChain = $this->loadCertificates($certPath))
			|| false ===($rootCertChain = $this->loadCertificates($rootCertPath))) {
			return;
		}
		foreach ($certChain as $pem) {
			if (isset($last_pem)) {
				if (false === $this->pem_signed_by_issuer($last_pem, $pem)
					|| false === $this->verifySignedCertificate($last_pem, $pem)) {
					return;
				}
			}
			$last_pem = $pem;
		}

		if (isset($last_pem)) {
			foreach ($rootCertChain as $pem) {
				if (true === $this->pem_signed_by_issuer($last_pem, $pem)) {
					if (true === $this->verifySignedCertificate($last_pem, $pem)) {
						$last_x509 = $this->pem_to_cert($last_pem);
						if ($last_x509['subject'] === $last_x509['issuer']) {
							$this->json['result']['value'] = 'valid-but-self-signed';
						} else {
							$this->json['result']['value'] = 'valid';
						}
					}
					return;
				}
			}
			$this->json['chain'][] = [
				'x509' => $this->pem_to_cert($last_pem),
				'signed_x509' => null,
				'verify' => false,
			];
			$this->json['result']['message'] = 'Signed certificate is not found';
		}
	}

	public function __construct()
	{
		$this->time = time();
		global $argv;
		$this->verifyCertificateChain($argv[1] ?? '', $argv[2] ?? openssl_get_cert_locations()['default_cert_file']);
		echo json_encode($this->json);
	}
}
