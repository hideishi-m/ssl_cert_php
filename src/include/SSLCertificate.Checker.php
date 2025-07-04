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

use \Bootstrap\Skeleton;

class Checker extends Skeleton
{
	use ErrorMessages, FilePath;

	protected Status $status = Status::Invalid;
	protected Certificate $cert;

	protected function createFromCertPath(string $path): false|Certificate
	{
		$text = $this->readTextFromFilePath($path, 'Certificate file');
		if (false === $text) {
			return false;
		}
		return new Certificate($text, Mode::Extended);
	}

	protected function checkCertificate(string $cert_path): bool
	{
		$cert = $this->createFromCertPath($cert_path);
		if (false === $cert) {
			return false;
		}
		$this->cert = $cert;
		if ($cert->isValid()) {
			if ($cert->isSelfSigned()) {
				$this->status = Status::SelfSigned;
			} else {
				$this->status = Status::Valid;
			}
		}
		return true;
	}

	protected function process(array $args): bool
	{
		$cert_path = $args[0] ?? '';
		return $this->checkCertificate($cert_path);
	}

	public function jsonSerialize(): mixed
	{
		$json = [
			'version' => VERSION,
			'result' => [
				'value' => $this->status->value,
				'message' => $this->getLastError(),
			],
		];
		if (! empty($this->cert)) {
			$json['x509'] = $this->cert;
			$json['sha1_fingerprint'] = $this->cert->sha1_fingerprint;
		}
		return $json;
	}
}
