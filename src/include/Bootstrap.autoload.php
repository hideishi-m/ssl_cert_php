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

namespace Bootstrap;

const VERSION = '1.0.0';

enum ReturnCode: int
{
	case Success = 0;
	case Failure = 1;
	case Parameter = 2;
	case Error = 255;
}

enum Command: string
{
	case Discovery = 'ssl_cert_discovery';
	case Checker = 'ssl_cert_check';
	case Verification = 'ssl_cert_verify';

	public function get_class_name(): string
	{
		return match($this) {
			Command::Discovery => '\\SSLCertificate\\Discovery',
			Command::Checker => '\\SSLCertificate\\Checker',
			Command::Verification => '\\SSLCertificate\\Verification',
		};
	}
}

function bootstrap()
{
	global $argv;
	$args = $argv;
	$command = array_shift($args);
	$command = basename($command);
	if ('index.php' === $command) {
		$command = array_shift($args) ?? '';
	}
	$pos = strpos($command, '.php');
	if (0 < $pos) {
		$command = substr($command, 0, $pos);
	}
	try {
		$command_name = Command::from($command);
	} catch (\ValueError $e) {
		error_log("{$command} command is not supported");
		exit(ReturnCode::Parameter);
	}
	$class_name = $command_name->get_class_name();
	$object = new $class_name();
	$code = $object->bootstrap($args);
	exit($code->value);
}
