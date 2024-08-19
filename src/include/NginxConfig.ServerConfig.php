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

namespace NginxConfig;

class ServerConfig implements \Countable, \IteratorAggregate, \JsonSerializable
{
	final const COMMENT_PATTERN = '/\s*((?<!\\\)#.*)?$/';
	final const SERVER_PATTERN = '/^\s*server\s+{/';
	final const SERVER_NAME_PATTERN = '/^\s*server_name\s+([^;]+)\s*;/';
	final const SSL_CERT_PATTERN = '/^\s*ssl_certificate\s+([^\s;]+)\s*;/';
	final const SSL_CERT_KEY_PATTERN = '/^\s*ssl_certificate_key\s+([^\s;]+)\s*;/';
	final const INCLUDE_PATTERN = '/^\s*include\s+([^\s;]+)\s*;/';

	protected array $block;
	protected string $root_dir;

	public readonly array $server_names;
	public readonly array $ssl_certs;
	public readonly array $ssl_cert_keys;
	public readonly array $server_certs;

	public static function stripComment(string $line): string
	{
		return preg_replace(self::COMMENT_PATTERN, '', $line);
	}

	public static function startsServerBlock(string $line): bool
	{
		return (1 === preg_match(self::SERVER_PATTERN, $line));
	}

	protected function getIncludeBlock(string $include): array
	{
		$block = [];
		if (0 !== strpos($include, '/')) {
			$include = "{$this->root_dir}/{$include}";
		}
		$file_iterator = new \GlobIterator($include);
		foreach ($file_iterator as $file_info) {
			$file_obj = $file_info->openFile('r');
			while (! $file_obj->eof()) {
				$line = $file_obj->fgets();
				$line = self::stripComment($line);
				if (! empty($line)) {
					$block[] = $line;
				}
			}
		}
		return $block;
	}

	public function getBlock(): string
	{
		return implode(PHP_EOL, $this->block);
	}

	public function getServerCerts(): array
	{
		if (! empty($this->server_names)
			&& ! empty($this->ssl_certs)) {
			$server_name = $this->server_names[0];
			foreach ($this->ssl_certs as $ssl_cert) {
				$server_certs[] = [
					'server_name' => $server_name,
					'ssl_certificate' => $ssl_cert,
				];
			}
		}
	}

	public function __construct(array $block, string $root_dir)
	{
		$this->block = $block;
		$this->root_dir = $root_dir;

		$server_names = [];
		$ssl_certs = [];
		$ssl_cert_keys = [];
		for ($i = 0; $i < count($this->block); $i++) {
			$line = $this->block[$i];
			if (preg_match(self::SERVER_NAME_PATTERN, $line, $match)) {
				foreach (preg_split('/\s+/', $match[1]) as $server_name) {
					if (! empty($server_name)) {
						$server_names[] = $server_name;
					}
				}
			} elseif (preg_match(self::SSL_CERT_PATTERN, $line, $match)) {
				$ssl_certs[] = $match[1];
			} elseif (preg_match(self::SSL_CERT_KEY_PATTERN, $line, $match)) {
				$ssl_cert_keys[] = $match[1];
			} elseif (preg_match(self::INCLUDE_PATTERN, $line, $match)) {
				$include_block = self::getIncludeBlock($match[1], $root_dir);
				array_splice($this->block, $i, 1, $include_block);
				--$i;
			}
		}

		$server_certs = [];
		if (! empty($server_names)
			&& ! empty($ssl_certs)) {
			$server_name = $server_names[0];
			foreach ($ssl_certs as $ssl_cert) {
				$server_certs[] = [
					'server_name' => $server_name,
					'ssl_certificate' => $ssl_cert,
				];
			}
		}

		$this->server_names = $server_names;
		$this->ssl_certs = $ssl_certs;
		$this->ssl_cert_keys = $ssl_cert_keys;
		$this->server_certs = $server_certs;
	}

	public function count(): int
	{
		return count($this->server_certs);
	}

	public function getIterator(): \Traversable
	{
		return new \ArrayIterator($this->server_certs);
	}

	public function jsonSerialize(): mixed
	{
		return $this->server_certs;
	}
}
