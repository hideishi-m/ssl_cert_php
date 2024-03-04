<?php
if (! isset($argv[1])) {
	error_log('argv[1] is not set');
	exit(1);
}

$script = $argv[1];
error_log("target is {$script}");

$phar = new Phar("{$script}.phar");
$phar->addFile(__DIR__ . "/src/{$script}.php", "/src/{$script}.php");
$phar->compressFiles(Phar::GZ);
$phar->setStub(createStub($script));
$phar->stopBuffering();
rename("{$script}.phar", $script);
chmod($script, 0755);

function createStub($script)
{
	$stub = <<<"EOF"
#!/usr/bin/env php
<?php
Phar::mapPhar('{$script}.phar');
include 'phar://{$script}.phar/src/{$script}.php';
__HALT_COMPILER();
EOF;
	return $stub;
}
