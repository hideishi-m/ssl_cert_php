<?php

abstract class SSLCertificateCommon implements JsonSerializable
{
	protected array $messages = [];

	public function get_last_error(): string
	{
		if ($length = count($this->messages)) {
			return $this->messages[$length - 1];
		} else {
			return '';
		}
	}

	public function jsonSerialize(): mixed
	{
	}
}

class SSLCertificate extends SSLCertificateCommon
{
	protected string $pem;
	protected array $x509;

	public readonly string $subject;
	public readonly string $issuer;
	public readonly int $not_before;
	public readonly int $not_after;

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

	public function __construct(string $pem)
	{
		$this->pem = $pem;
		$this->x509 = openssl_x509_parse($this->pem);

		$this->subject = $this->array_to_string($this->x509['subject']);
		$this->issuer = $this->array_to_string($this->x509['issuer']);
		$this->not_before = intval($this->x509['validFrom_time_t']);
		$this->not_after = intval($this->x509['validTo_time_t']);
	}

	public function is_valid(): bool
	{
		$time = time();
		return ($this->not_before < $time && $time < $this->not_after);
	}

	public function is_signed_by(self $signed_cert): bool
	{
		return $this->issuer === $signed_cert->subject;
	}

	public function is_self_signed(): bool
	{
		return $this->issuer === $this->subject;
	}

	public function get_publickey(): OpenSSLAsymmetricKey
	{
		return openssl_pkey_get_public($this->pem);
	}

	public function verify_signed_by(self $signed_cert): bool
	{
		if (false === $this->is_valid()) {
			$this->messages[] = 'Certificate is expired';
			return false;
		}

		if (false === $signed_cert->is_valid()) {
			$this->messages[] = 'Signed certificate is expired';
			return false;
		}

		if (1 !== openssl_x509_verify($this->pem, $signed_cert->get_publickey())) {
			$this->messages[] = 'Certificate is not signed by public key of signed certificate';
			return false;
		}
		return true;
	}

	public function jsonSerialize(): mixed
	{
		return [
			'subject' => $this->subject,
			'issuer' => $this->issuer,
			'not_before' => [
				'timestamp' => $this->not_before,
			],
			'not_after' => [
				'timestamp' => $this->not_after,
			],
			# 'raw' => $this->x509,
		];
	}
}

class SSLCertificateCollection extends SSLCertificateCommon implements Countable, Iterator
{
	protected int $position;

	protected array $pems = [];
	protected array $certs = [];

	public function __construct(string $pem)
	{
		$this->position = 0;
		if (false === preg_match_all('#-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----#s', $pem, $matches)) {
			$this->messages = 'Certificate file is not valid';
		} else {
			$this->pems = $matches[0];
			foreach ($this->pems as $pem) {
				$this->certs[] = new SSLCertificate($pem);
			}
		}
	}

	public function search(string $key, mixed $value): false|SSLCertificate
	{
		foreach ($this as $index => $cert) {
			if (property_exists($cert, $key)
				&& $value === $cert->{$key}) {
				return $cert;
			}
		}
		return false;
	}

	public function count(): int
	{
		return count($this->certs);
	}

	public function rewind(): void
	{
		$this->position = 0;
	}

	public function current()
	{
		return $this->certs[$this->position];
	}

	public function key()
	{
		return $this->position;
	}

	public function next(): void
	{
		++$this->position;
	}

	public function valid(): bool
	{
		return isset($this->pems[$this->position]);
	}

	public function jsonSerialize(): mixed
	{
		return $this->certs;
	}
}

class SSLCertificateVerify extends SSLCertificateCommon
{
	final const STATUS = [
		-1 => 'valid-but-self-signed',
		 0 => 'invalid',
		 1 => 'valid',
	];
	
	protected int $status = 0;
	protected array $chain = [];

	protected function get_ca_certs_path(): string
	{
		return openssl_get_cert_locations()['default_cert_file'];
	}

	protected function load_certs_file(string $certs_path): false|SSLCertificateCollection
	{
		if (empty($certs_path)) {
			$this->messages = 'Certificate file is not specified';
			return false;
		} elseif (! is_file($certs_path)) {
			$this->messages = 'Certificate file does not exist';
			return false;
		} elseif (! is_readable($certs_path)) {
			$this->messages = 'Certificate file is not readable';
			return false;
		}

		$pem = file_get_contents($certs_path);
		if (empty($pem)) {
			$this->messages = 'Certificate file is not valid';
			return false;
		}

		return new SSLCertificateCollection($pem);
	}

	protected function verify_chain(string $chain_certs_path, string $ca_certs_path): bool
	{
		$chain_certs = $this->load_certs_file($chain_certs_path);
		if (false === $chain_certs) {
			return false;
		}

		foreach ($chain_certs as $index => $cert) {
			if ($index > 0) {
				$this->chain[$index - 1]['signed_x509'] = $cert;
				$subject_cert = $this->chain[$index - 1]['x509'];
				if (false === $subject_cert->is_signed_by($cert)) {
					$this->messages[] = 'Certificate is not signed by signed certificate';
					return false;
				} elseif (false === $subject_cert->verify_signed_by($cert)) {
					$this->messages[] = $subject_cert->get_last_error();
					return false;
				} else {
					$this->chain[$index - 1]['verified'] = true;
				}
			}
			$this->chain[] = [
				'x509' => $cert,
				'signed_x509' => null,
				'verified' => false,
			];
		}

		$ca_certs = $this->load_certs_file($ca_certs_path);
		if (false === $ca_certs) {
			return false;
		}

		$subject_cert = $this->chain[count($this->chain) - 1]['x509'];
		foreach ($ca_certs as $signed_cert) {
			if (false === $subject_cert->is_signed_by($signed_cert)) {
				continue;
			} elseif ($subject_cert->verify_signed_by($signed_cert)) {
				$this->chain[count($this->chain) - 1]['signed_x509'] = $signed_cert;
				$this->chain[count($this->chain) - 1]['verified'] = true;
				if ($subject_cert->is_self_signed()) {
					$this->status = -1;
					return true;
				} else {
					$this->status = 1;
					return true;
				}
			} else {
				$this->messages[] = $subject_cert->get_last_error();
				return false;
			}
		}

		$this->messages[] = 'Signed certificate is not found';
		return false;
	}

	public function __construct()
	{
		global $argv;
		$this->verify_chain($argv[1] ?? '', $argv[2] ?? $this->get_ca_certs_path());
		echo json_encode($this);
	}

	public function jsonSerialize(): mixed
	{
		return [
			'result' => [
				'value' => self::STATUS[$this->status],
				'message' => $this->get_last_error(),
			],
			'chain' => $this->chain,
		];
	}
}

new SSLCertificateVerify();
