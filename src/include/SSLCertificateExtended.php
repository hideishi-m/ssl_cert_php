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

require_once __DIR__ . '/SSLCertificate.php';

class SSLCertificateExtended extends SSLCertificate
{
	protected string $text;

	public readonly int $version;
	public readonly string $serial_number;
	public readonly string $signature_algorithm;
	public readonly string $alternative_names;
	public readonly string $public_key_algorithm;
	public readonly string $sha1_fingerprint;

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
			return (new DateTimeImmutable($output))->getTimestamp();
		} else {
			return 0;
		}
	}

	public function __construct(string $pem)
	{
		parent::__construct($pem);

		if (false === openssl_x509_export($pem, $text, FALSE)) {
			$this->messages[] = 'Certificate file is not valid';
			return;
		}
		$this->text = $text;
		$this->version = $this->filterVersion($this->matchInLine('Version', $this->text));
		$this->serial_number = $this->matchNextLine('Serial Number', $this->text);
		$this->signature_algorithm = $this->matchInLine('Signature Algorithm', $this->text);
		$this->alternative_names = $this->matchNextLine('X509v3 Subject Alternative Name', $this->text);
		$this->public_key_algorithm = $this->matchInLine('Public Key Algorithm', $this->text);

		if (false === ($fingerprint = openssl_x509_fingerprint($pem, 'sha1'))) {
			$this->messages[] = 'Certificate file is not valid';
			return;
		}
		$this->sha1_fingerprint = preg_replace('#(..)(?=..)#', '$1:', $fingerprint);
	}

	public function jsonSerialize(): mixed
	{
		return [
			'version' => $this->version,
			'serial_number' => $this->serial_number,
			'signature_algorithm' => $this->signature_algorithm,
			'issuer' => $this->issuer,
			'not_before' => [
				'datetime' => (new \DateTimeImmutable("@{$this->not_before}"))->format(DateTimeInterface::W3C),
				'timestamp' => $this->not_before,
			],
			'not_after' => [
				'datetime' => (new \DateTimeImmutable("@{$this->not_after}"))->format(DateTimeInterface::W3C),
				'timestamp' => $this->not_after,
			],
			'subject' => $this->subject,
			'alternative_names' => $this->alternative_names,
			'public_key_algorithm' => $this->public_key_algorithm,
		];
	}
}
