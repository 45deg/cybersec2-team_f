<?php
/* 組み込み簡易サーバー */
/* php -t sample -S localhost:8080 */

$code = $_GET['code'];

/* vuln: localhost:8080/test2.php?code=hello;%20ls&ev=shell_exec(%22ls%22); */

/* http://php.net/manual/ja/ref.exec.php */
print '[exec]' . '<br>';
exec("echo ${code}", $output);
print implode(' ', $output);

print '<hr>';

print '[shell_exec]' . '<br>';
print shell_exec('echo ' . $code);

print '<hr>';

// これは検出したくない
print '[shell_exec with escapeshellarg]' . '<br>';
print shell_exec('echo ' . escapeshellarg($code));

print '<hr>';

// これは検出したくない
print '[shell_exec with escapeshellcmd]' . '<br>';
print shell_exec(escapeshellcmd("echo $code"));

print '<hr>';

print '[passthru]' . '<br>';
passthru("echo {$code}");

print '<hr>';

print '[system]' . '<br>';
system('echo ' . $code);

print '<hr>';

/*
print '[system2]' . '<br>';

$name = "system";
$name("echo " . $code); 
// \Node\Expr\FuncCall
// $node->name が \Node\Expr\Variable

print '<hr>';

print '[system3]' . '<br>';

$name = ["system"];
$name[0]("echo " . $code); 
// \Node\Expr\FuncCall
// $node->name が \Node\Expr\ArrayDimFetch

print '<hr>';

class Hoge {
  public function f1() { 
    return "system";
  }
}
$hoge = new Hoge;
//((string)$hoge->f1())("echo " . $code);
*/


print '[Backtick]' . '<br>';
print `echo $code`;

print '<hr>';

// ; でコマンドつなげても無理っぽい
print '[popen]' . '<br>';

$handle = popen("echo " . $code, "r");
$read = fread($handle, 2096);
echo $read;
pclose($handle);

print '<hr>';

print '[proc_open]' . '<br>';

$descriptorspec = array(
  0 => array("pipe", "r"),
  1 => array("pipe", "w"),
  2 => array("pipe", "w")
);

$process = proc_open('echo ' . $code, $descriptorspec, $pipes);
if (is_resource($process)) {
  fclose($pipes[0]);

  echo stream_get_contents($pipes[1]);
  fclose($pipes[1]);
  echo stream_get_contents($pipes[2]);
  fclose($pipes[2]);
  
  $return_value = proc_close($process);
  //echo "command returned $return_value\n";
}

print '<hr>';

// require: -enable-pcntl
// これも ; でコマンドつなげてもダメっぽい
//print '[pcntl_exec]' . '<br>';
//pcntl_exec('ls', array($code));
//
//print '<hr>';


$ev = $_GET['ev'];

print '[preg_replace]' . '<br>';
print preg_replace('/(.*)/e', $ev, '');

print '<hr>';

print '[create_function]' . '<br>';

$f = create_function('', "return $ev");
print $f();

print '<hr>';
