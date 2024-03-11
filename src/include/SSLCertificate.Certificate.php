<?php
/**
 * Copyright (c) 2024 Hidenori ISHIKAWA. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace SSLCertificate;

class Certificate extends Common
{
	protected CertificateMode $mode;

	protected string $pem;
	protected array $x509;
	protected string $text;

	// Simple
	public readonly string $common_name;

	// Default
	public readonly string $subject;
	public readonly string $issuer;
	public readonly int $not_before;
	public readonly int $not_after;

	// Extended
	public readonly int $version;
	public readonly string $serial_number;
	public readonly string $signature_algorithm;
	public readonly string $alternative_names;
	public readonly string $public_key_algorithm;
	public readonly string $sha1_fingerprint;

	protected  function arrayToString(array $array): string
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

	protected  function matchInLine(string $needle, string $text): string
	{
		$output = '';
		$regex = '#^\s*' . preg_quote($needle, '#') . ': (.+)$#m';
		if (preg_match($regex, $text, $match)) {
			$output = $match[1];
		}
		return $output;
	}

	protected  function matchNextLine(string $needle, string $text): string
	{
		$output = '';
		$regex = '#^\s*' . preg_quote($needle, '#') . ':\s+(.+)$#m';
		if (preg_match($regex, $text, $match)) {
			$output = $match[1];
		}
		return $output;
	}

	protected  function filterVersion(string $output): int
	{
		if ('' !== $output
			&& preg_match('#^(\d+)#', $output, $match)) {
			$output = $match[1];
		}
		return intval($output);
	}

	protected  function filterTimestamp(string $output): int
	{
		if ('' !== $output) {
			return (new \DateTimeImmutable($output))->getTimestamp();
		} else {
			return 0;
		}
	}

	public function __construct(string $pem, CertificateMode $mode = CertificateMode::Default)
	{
		$this->mode = $mode;

		// Simple
		$this->pem = $pem;
		$x509 = openssl_x509_parse($this->pem);
		if (false === $x509) {
			throw new Exception('Certificate file is not valid: ' . openssl_error_string());
		}
		$this->x509 = $x509;
		$this->common_name = $this->x509['subject']['CN'] ?? '';
		if (CertificateMode::Default->value > $this->mode) {
			return;
		}

		// Default
		$this->subject = $this->arrayToString($this->x509['subject']);
		$this->issuer = $this->arrayToString($this->x509['issuer']);
		$this->not_before = intval($this->x509['validFrom_time_t']);
		$this->not_after = intval($this->x509['validTo_time_t']);
		if (CertificateMode::Extended->value > $this->mode) {
			return;
		}

		// Extended
		if (false === openssl_x509_export($pem, $text, FALSE)) {
			throw new Exception('Certificate file is not valid: ' . openssl_error_string());
		}
		$this->text = $text;

		$this->version = $this->filterVersion($this->matchInLine('Version', $this->text));
		$this->serial_number = $this->matchNextLine('Serial Number', $this->text);
		$this->signature_algorithm = $this->matchInLine('Signature Algorithm', $this->text);
		$this->alternative_names = $this->matchNextLine('X509v3 Subject Alternative Name', $this->text);
		$this->public_key_algorithm = $this->matchInLine('Public Key Algorithm', $this->text);

		if (false === ($fingerprint = openssl_x509_fingerprint($pem, 'sha1'))) {
			throw new Exception('Certificate file is not valid: ' . openssl_error_string());
		}
		$this->sha1_fingerprint = preg_replace('#(..)(?=..)#', '$1:', $fingerprint);
	}

	public function isValid(): bool
	{
		$time = time();
		return ($this->not_before < $time && $time < $this->not_after);
	}

	public function isSignedWith(self $signed_cert): bool
	{
		return $this->issuer === $signed_cert->subject;
	}

	public function isSelfSigned(): bool
	{
		return $this->issuer === $this->subject;
	}

	public function getPublicKey(): \OpenSSLAsymmetricKey
	{
		return openssl_pkey_get_public($this->pem);
	}

	public function verifySignedWith(self $signed_cert): bool
	{
		if (false === $this->isValid()) {
			$this->messages[] = 'Certificate is expired';
			return false;
		}

		if (false === $signed_cert->isValid()) {
			$this->messages[] = 'Signed certificate is expired';
			return false;
		}

		if (1 !== openssl_x509_verify($this->pem, $signed_cert->getPublicKey())) {
			$this->messages[] = 'Certificate is not signed by public key of signed certificate';
			return false;
		}
		return true;
	}

	public function jsonSerialize(): mixed
	{
		// Simple
		$json = [
			'common_name' => $this->common_name,
			# 'raw' => $this->x509,
		];
		if (CertificateMode::Default->value > $this->mode) {
			return $json;
		}

		// Default
		foreach ([
			'subject' => $this->subject,
			'issuer' => $this->issuer,
			'not_before' => [
				'datetime' => (new \DateTimeImmutable("@{$this->not_before}"))->format(\DateTimeInterface::W3C),
				'timestamp' => $this->not_before,
			],
			'not_after' => [
				'datetime' => (new \DateTimeImmutable("@{$this->not_after}"))->format(\DateTimeInterface::W3C),
				'timestamp' => $this->not_after,
			],
		] as $key => $value) {
			$json[$key] = $value;
		}
		if (CertificateMode::Extended->value > $this->mode) {
			return $json;
		}

		// Extended
		foreach ([
			'version' => $this->version,
			'serial_number' => $this->serial_number,
			'signature_algorithm' => $this->signature_algorithm,
			'alternative_names' => $this->alternative_names,
			'public_key_algorithm' => $this->public_key_algorithm,
		] as $key => $value) {
			$json[$key] = $value;
		}

		return $json;
	}
}
