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

namespace NginxConf;

class ConfigFile implements \Countable, \Iterator
{
	protected int $position;

	protected string $config_path;
	protected string $root_dir = '';
	protected array $server_configs = [];

	protected function loadRootDir(): void
	{
		$pos = strpos($this->config_path, '/nginx/conf.d/');
		if (false !== $pos) {
			$this->root_dir = substr($this->config_path, 0, $pos) . '/nginx';
		}
	}

	protected function appendServerConfig(array $block): void
	{
		$this->server_configs[] = new ServerConfig($block, $this->root_dir);
	}

	protected function loadServerConfigs(): void
	{
		$lines = file($this->config_path);
		if (false !== $lines) {
			$block = [];
			$has_server = false;
			foreach ($lines as $line) {
				$line = ServerConfig::stripComment($line);
				if (ServerConfig::startsServerBlock($line)) {
					if ($has_server) {
						$this->appendServerConfig($block);
					}
					$block = [];
					$has_server = true;
				}
				if (! empty($line)) {
					$block[] = $line;
				}
			}
			if ($has_server) {
				$this->appendServerConfig($block);
			}
		}
	}

	public function __construct(string $config_path)
	{
		$this->config_path = $config_path;
		$this->loadRootDir();
		$this->loadServerConfigs();
	}

	public function count(): int
	{
		return count($this->server_configs);
	}

	public function current()
	{
		return $this->server_configs[$this->position];
	}

	public function key()
	{
		return $this->position;
	}

	public function next(): void
	{
		++$this->position;
	}

	public function rewind(): void
	{
		$this->position = 0;
	}

	public function valid(): bool
	{
		return isset($this->server_configs[$this->position]);
	}
}
