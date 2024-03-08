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
	protected string $pem;
	protected array $x509;

	public readonly string $subject;
	public readonly string $issuer;
	public readonly int $not_before;
	public readonly int $not_after;

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

	public function __construct(string $pem)
	{
		$this->pem = $pem;
		$x509 = openssl_x509_parse($this->pem);
		if (false === $x509) {
			throw new Exception('Certificate file is not valid: ' . openssl_error_string());
		}
		$this->x509 = $x509;

		$this->subject = $this->arrayToString($this->x509['subject']);
		$this->issuer = $this->arrayToString($this->x509['issuer']);
		$this->not_before = intval($this->x509['validFrom_time_t']);
		$this->not_after = intval($this->x509['validTo_time_t']);
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
		return [
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
			# 'raw' => $this->x509,
		];
	}
}
