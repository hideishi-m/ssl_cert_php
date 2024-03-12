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

class Verification extends Skeleton
{
	use ErrorMessages, FilePath;

	protected Status $status = Status::Invalid;
	protected array $chain = [];

	protected function getDefaultCACertsPath(string $ca_path): string
	{
		if (!empty($ca_path)) {
			return $ca_path;
		} else {
			return openssl_get_cert_locations()['default_cert_file'];
		}
	}

	protected function createFromCertsPath(string $path): false|Collection
	{
		$text = $this->readTextFromFilePath($path);
		if (false === $text) {
			return false;
		}
		return new Collection($text, Mode::Default);
	}

	protected function verifyChain(string $chain_path, string $ca_path): bool
	{
		$chain_certs = $this->createFromCertsPath($chain_path);
		if (false === $chain_certs
			|| 0 === count($chain_certs)) {
			return false;
		}

		foreach ($chain_certs as $index => $cert) {
			if ($index > 0) {
				$this->chain[$index - 1]['signed_x509'] = $cert;
				$subject_cert = $this->chain[$index - 1]['x509'];
				if (false === $subject_cert->isSignedWith($cert)) {
					$this->messages[] = 'Certificate is not signed by signed certificate';
					return false;
				} elseif (false === $subject_cert->verifySignedWith($cert)) {
					$this->messages[] = $subject_cert->getLastError();
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

		$ca_certs = $this->createFromCertsPath($ca_path);
		if (false === $ca_certs
			|| 0 === count($chain_certs)) {
			return false;
		}

		$subject_cert = $this->chain[count($this->chain) - 1]['x509'];
		foreach ($ca_certs as $signed_cert) {
			if (false === $subject_cert->isSignedWith($signed_cert)) {
				continue;
			} elseif ($subject_cert->verifySignedWith($signed_cert)) {
				$this->chain[count($this->chain) - 1]['signed_x509'] = $signed_cert;
				$this->chain[count($this->chain) - 1]['verified'] = true;
				if ($subject_cert->isSelfSigned()) {
					$this->status = Status::SelfSigned;
					return true;
				} else {
					$this->status = Status::Valid;
					return true;
				}
			} else {
				$this->messages[] = $subject_cert->getLastError();
				return false;
			}
		}

		$this->messages[] = 'Signed certificate is not found';
		return false;
	}

	protected function process(array $args): bool
	{
		$chain_path = $args[0] ?? '';
		$ca_path = $args[1] ?? '';
		$ca_path = $this->getDefaultCACertsPath($ca_path);
		return $this->verifyChain($chain_path, $ca_path);
	}

	public function jsonSerialize(): mixed
	{
		return [
			'version' => VERSION,
			'result' => [
				'value' => $this->status->value,
				'message' => $this->getLastError(),
			],
			'chain' => $this->chain,
		];
	}
}
