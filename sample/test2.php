<?php
/* 組み込み簡易サーバー */
/* php -t sample -S localhost:8080 */

$code = $_GET['code'];

/* vuln: localhost:8080/test2.php?code=hello;%20ls */

/* http://php.net/manual/ja/ref.exec.php */
print '[exec]' . '<br>';
exec("echo ${code}", $output);
print implode(' ', $output);

print '<hr>';

print '[shell_exec]' . '<br>';
print shell_exec('echo ' . $code);

print '<hr>';

print '[shell_exec with escapeshellarg]' . '<br>';
print shell_exec('echo ' . escapeshellarg($code));

print '<hr>';

print '[shell_exec with escapeshellcmd]' . '<br>';
print shell_exec(escapeshellcmd("echo $code"));

print '<hr>';

print '[passthru]' . '<br>';
passthru("echo {$code}");

print '<hr>';

print '[system]' . '<br>';
system('echo ' . $code);

print '<hr>';
