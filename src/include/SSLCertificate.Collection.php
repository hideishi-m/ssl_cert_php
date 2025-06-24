<?php
/**
 * Copyright (c) 2024 Hidenori ISHIKAWA. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace SSLCertificate;

class Collection implements \Countable, \IteratorAggregate, \JsonSerializable
{
	use ErrorMessages;

	protected array $pems = [];
	protected array $certs = [];

	public function search(string $key, mixed $value): false|Certificate
	{
		foreach ($this as $index => $cert) {
			if (property_exists($cert, $key)
				&& $value === $cert->{$key}) {
				return $cert;
			}
		}
		return false;
	}

	public function __construct(string $pem, $mode = Mode::Default)
	{
		if (false === preg_match_all('#-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----#s', $pem, $matches)) {
			$this->messages[] = 'Certificate file is not valid';
		} else {
			$this->pems = $matches[0];
			foreach ($this->pems as $pem) {
				$this->certs[] = new Certificate($pem, $mode);
			}
		}
	}

	public function count(): int
	{
		return count($this->certs);
	}

	public function getIterator(): \Iterator
	{
		foreach ($this->certs as $cert) {
			yield $cert;
		}
	}

	public function jsonSerialize(): mixed
	{
		return $this->certs;
	}
}
