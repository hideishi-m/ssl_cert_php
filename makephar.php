<?php

if (! isset($argv[1])) {
	error_log('argv[1] is not set');
	exit(1);
}

$script = $argv[1];
error_log("target is {$script}");
$pharfile = "{$script}.phar";
if (is_file($pharfile)) {
	unlink($pharfile);
}
$phar = new Phar($pharfile);
$phar->buildFromDirectory(__DIR__ . '/src/', '#/include/[^/]+\.php$#');
$phar->addFile(__DIR__ . "/src/{$script}.php", '/index.php');
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
include 'phar://{$script}.phar/index.php';
__HALT_COMPILER();
EOF;
	return $stub;
}
