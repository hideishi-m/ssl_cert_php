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

class Discovery extends Common
{
	final const OS_FREEBSD = 'FreeBSD';
	final const OS_LINUX = 'Linux';

	final const CONF_DIR_FREEBSD = '/usr/local/etc/nginx/conf.d';
	final const CONF_DIR_LINUX = '/etc/nginx/conf.d';
	final const CONF_DIR_KUSANAGI = '/etc/opt/kusanagi/nginx/conf.d';

	protected array $certs = [];

	protected function getDefaultNginxConfDir(): string
	{
		if (self::OS_FREEBSD === PHP_OS) {
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

	protected function discoverNginxConfDir(string $conf_dir): bool
	{
		if (empty($conf_dir)) {
			$this->messages[] = 'Configuration directory is not specified';
			return false;
		} elseif (! is_dir($conf_dir)) {
			$this->messages[] = 'Configuration directory does not exist';
			return false;
		} elseif (! is_readable($conf_dir)) {
			$this->messages[] = 'Configuration directory is not readable';
			return false;
		}

		$cert_paths = [];
		$dir_iterator = new \RecursiveDirectoryIterator($conf_dir);
		$dir_iterator->setInfoClass(\NginxConf\FileInfo::class);
		$filter_iterator = new \RecursiveRegexIterator($dir_iterator, '#\.conf$#');
		$file_iterator = new \RecursiveIteratorIterator($filter_iterator);
		foreach ($file_iterator as $file_info) {
			foreach ($file_info->getServerConfigs(false) as $server_conf) {
				foreach ($server_conf->getServerCerts() as $server_cert) {
					$pem = file_get_contents($server_cert['ssl_certificate']);
					$x509 = openssl_x509_parse($pem);
					if (false !== $x509) {
						$this->certs[] = [
							'{#SERVERNAME}' => $server_cert['server_name'],
							'{#CERTNAME}' => $x509['subject']['CN'],
							'{#CERTPATH}' => $server_cert['ssl_certificate'],
						];
					}
				}
			}
		}

		return true;
	}

	public function __construct(string $conf_dir)
	{
		try {
			$conf_dir = $conf_dir ?: $this->getDefaultNginxConfDir();
			$this->discoverNginxConfDir($conf_dir);
		} catch (\Exception $e) {
			error_log($e);
		}
		echo json_encode($this);
	}

	public function jsonSerialize(): mixed
	{
		return $this->certs;
	}
}
