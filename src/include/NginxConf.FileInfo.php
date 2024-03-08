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

namespace NginxConf;

class FileInfo extends \SplFileInfo
{
	protected bool $_root_dir_loaded = false;
	protected string $root_dir;
	protected bool $_server_configs_loaded = false;
	protected array $server_configs = [];

	protected function getDefaultRootDir(): string
	{
		$conf_path = $this->getPathname();
		$pos = strpos($conf_path, '/nginx/conf.d/');
		if (false !== $pos) {
			return substr($conf_path, 0, $pos) . '/nginx';
		}
		return '';
	}

	protected function loadRootDir(): void
	{
		if ($this->_root_dir_loaded) {
			return;
		}
		$this->root_dir = $this->getDefaultRootDir();
		$this->_root_dir_loaded = true;
	}

	protected function appendServerConfig(array $block): void
	{
		$this->loadRootDir();
		$server_config = ServerConfig::createFromBlock($block, $this->root_dir);
		if (false !== $server_config) {
			$this->server_configs[] = $server_config;
		}
	}

	protected function loadServerConfigs(): void
	{
		if ($this->_server_configs_loaded) {
			return;
		}
		$file_obj = $this->openFile('r');
		if ($file_obj) {
			$block = [];
			while (! $file_obj->eof()) {
				$line = $file_obj->fgets();
				$line = preg_replace(ServerConfig::COMMENT_PATTERN, '', $line);
				if (preg_match(ServerConfig::SERVER_PATTERN, $line)) {
					$this->appendServerConfig($block);
					$block = [];
				}
				if (! empty($line)) {
					$block[] = $line;
				}
			}
			$this->appendServerConfig($block);
		}
		$this->_server_configs_loaded = true;
	}

	public function getServerConfigs(): array
	{
		$this->loadServerConfigs();
		return $this->server_configs;
	}
}
