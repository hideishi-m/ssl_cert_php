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

use \NginxConf\ConfigFile;

class Discovery extends Bootstrap
{
	use ErrorMessages, DirectoryPath, FilePath;

	final const OS_FREEBSD = 'FreeBSD';
	final const OS_LINUX = 'Linux';

	final const CONF_DIR_FREEBSD = '/usr/local/etc/nginx/conf.d';
	final const CONF_DIR_LINUX = '/etc/nginx/conf.d';
	final const CONF_DIR_KUSANAGI = '/etc/opt/kusanagi/nginx/conf.d';

	protected array $certs = [];

	protected function getDefaultNginxConfDir(string $conf_dir): string
	{
		if (! empty($conf_dir)) {
			return $conf_dir;
		} elseif (self::OS_FREEBSD === PHP_OS) {
			return self::CONF_DIR_FREEBSD;
		} elseif (self::OS_LINUX === PHP_OS) {
			if (false === strpos(PHP_PREFIX, '/kusanagi/')) {
				return self::CONF_DIR_LINUX;
			} else {
				return self::CONF_DIR_KUSANAGI;
			}
		} else {
			return '';
		}
	}

	protected function createFromCertPath(string $path): false|Certificate
	{
		$text = $this->readTextFromFilePath($path, 'Certificate file');
		if (false === $text) {
			return false;
		}
		return new Certificate($text, Mode::Simple);
	}

	protected function discoverNginxConfDir(string $conf_dir): bool
	{
		$iterator = $this->getIteratorFromDirectoryPath($conf_dir, '#\.conf$#', 'Configuration directory');
		if (false === $iterator) {
			return false;
		}
		foreach ($iterator as $file_info) {
			$config_file = new ConfigFile($file_info->getPathname());
			foreach ($config_file as $server_conf) {
				foreach ($server_conf as $server_cert) {
					$cert = $this->createFromCertPath($server_cert['ssl_certificate'], Mode::Simple);
					if (! empty($cert->common_name)) {
						$this->certs[] = [
							'{#SERVERNAME}' => $server_cert['server_name'],
							'{#CERTNAME}' => $cert->common_name,
							'{#CERTPATH}' => $server_cert['ssl_certificate'],
						];
					}
				}
			}
		}

		return true;
	}

	protected function process(array $argv): bool
	{
		$conf_dir = $this->getDefaultNginxConfDir($argv[1] ?? '');
		return $this->discoverNginxConfDir($conf_dir);
	}

	public function jsonSerialize(): mixed
	{
		return $this->certs;
	}
}
