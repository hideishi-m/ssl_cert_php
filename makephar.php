<?php

if (! isset($argv[1])) {
	error_log('argv[1] is not set');
	exit(1);
}

$script = $argv[1];
error_log("target is {$script}");
$pharfile = "{$script}.phar";
$pattern = '#/(include|' . preg_quote($script, '#') . ')/[^/]+\.php$#';
var_dump($pattern);

if (is_file($pharfile)) {
	unlink($pharfile);
}
$phar = new Phar("{$script}.phar");
$phar->buildFromDirectory(__DIR__ . '/src/', $pattern);
$phar->compressFiles(Phar::GZ);
$phar->setStub(createStub($script));
$phar->stopBuffering();
rename($pharfile, $script);
chmod($script, 0755);

function createStub($script)
{
	$stub = <<<"EOF"
#!/usr/bin/env php
<?php
Phar::mapPhar('{$script}.phar');
include 'phar://{$script}.phar/{$script}/index.php';
__HALT_COMPILER();
EOF;
	return $stub;
}
