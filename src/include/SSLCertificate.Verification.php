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

class Verification extends Common
{
	protected int $status = CERTIFICATE_INVALID;
	protected array $chain = [];

	protected function getCACertsPath(): string
	{
		return openssl_get_cert_locations()['default_cert_file'];
	}

	protected function loadCertsPath(string $certs_path): false|Collection
	{
		if (empty($certs_path)) {
			$this->messages[] = 'Certificate file is not specified';
			return false;
		} elseif (! is_file($certs_path)) {
			$this->messages[] = 'Certificate file does not exist';
			return false;
		} elseif (! is_readable($certs_path)) {
			$this->messages[] = 'Certificate file is not readable';
			return false;
		}

		$pem = file_get_contents($certs_path);
		if (empty($pem)) {
			$this->messages[] = 'Certificate file is not valid';
			return false;
		}

		return new Collection($pem);
	}

	protected function verifyChain(string $chain_path, string $ca_path): bool
	{
		$chain_certs = $this->loadCertsPath($chain_path);
		if (false === $chain_certs) {
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

		$ca_certs = $this->loadCertsPath($ca_path);
		if (false === $ca_certs) {
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
					$this->status = CERTIFICATE_SELF_SIGNED;
					return true;
				} else {
					$this->status = CERTIFICATE_VALID;
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

	public function __construct(string $chain_path, string $ca_path)
	{
		try {
			$ca_path = $ca_path ?: $this->getCACertsPath();
			$this->verifyChain($chain_path, $ca_path);
		} catch (\Exception $e) {
			error_log($e);
		}
		echo json_encode($this);
	}

	public function jsonSerialize(): mixed
	{
		return [
			'version' => VERSION,
			'result' => [
				'value' => CERTIFICATE_STATUS[$this->status],
				'message' => $this->getLastError(),
			],
			'chain' => $this->chain,
		];
	}
}
