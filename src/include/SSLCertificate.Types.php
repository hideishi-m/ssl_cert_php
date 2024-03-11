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

const VERSION = '1.0.0';

enum CertificateStatus: string
{
	case SelfSigned = 'valid-but-self-signed';
	case Invalid = 'invalid';
	case Valid = 'valid';
}

enum CertificateMode: int
{
	case Simple = 0;
	case Default = 1;
	case Extended = 2;
}

trait ErrorMessages
{
	protected array $messages = [];

	public function getLastError(): string
	{
		if ($length = count($this->messages)) {
			return $this->messages[$length - 1];
		} else {
			return '';
		}
	}
}

trait LoadCertificate
{
	use ErrorMessages;

	protected function loadCertPath(
		string $cert_path,
		CertificateMode $cert_mode = CertificateMode::Default,
		string $class = Certificate::class
	): false|Certificate|Collection
	{
		if (empty($cert_path)) {
			$this->messages[] = 'Certificate file is not specified';
			return false;
		} elseif (! is_file($cert_path)) {
			$this->messages[] = 'Certificate file does not exist';
			return false;
		} elseif (! is_readable($cert_path)) {
			$this->messages[] = 'Certificate file is not readable';
			return false;
		}

		$pem = file_get_contents($cert_path);
		if (empty($pem)) {
			$this->messages[] = 'Certificate file is not valid';
			return false;
		}

		return new $class($pem, $cert_mode);
	}
}
