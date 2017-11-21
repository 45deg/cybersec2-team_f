<?php

/* ライブラリ読み込み */
require_once "vendor/autoload.php";
require_once "lib/bootstrap.php";


// -f="path"  : 検査対象
// -s         : コード片表示をなくす
// -n 3       : コード片表示行数
$options = getopt("f:sn::");
if(empty($options)) {
  $path = $argv[1];
  if(!isset($path)) die('Input a file or directory.');
  $simple = FALSE;
  $hunk = 3;
} else {
  $path = $options['f'];
  $simple = isset($options['s']) ? TRUE : FALSE;
  $hunk = isset($options['n']) ? (int)$options['n'] : 3;
  //var_dump($options);
}

function check($filename, $simple, $hunk) {

/* ファイル読み込み */
$code = file_get_contents($filename);
if($code === FALSE) {
  fputs(STDERR, "Cannot load a file $filename" . PHP_EOL);
}

$position = new VulnChecker\PositionStore($code);

$traverser = new PhpParser\NodeTraverser;
$traverser->addVisitor(new VulnChecker\TaintVisitor);
$traverser->addVisitor(new VulnChecker\Visitor($position, $simple, $hunk));

/* パース */
$lexer = new PhpParser\Lexer(array(
  'usedAttributes' => array('startLine', 'startFilePos')
));
$parser = (new PhpParser\ParserFactory)->create(
                PhpParser\ParserFactory::PREFER_PHP5, $lexer);
try {
  $ast = $parser->parse($code);
  $traverser->traverse($ast);
} catch (PhpParser\Error $error) {
  fputs(STDERR, "Parse error: {$error->getMessage()}" . PHP_EOL);
}

}

function isPHPFile($filename) {
  $ext = substr($filename, strrpos($filename, '.') + 1);
  return $ext == "php";
}

function checkDirectory($path, $simple, $hunk) {
  $files = scandir($path);
  foreach($files as $file) {
    $fullpath = "$path/$file";
    if(is_file($fullpath) && isPHPFile($file)) {
      print "===========================" . PHP_EOL;
      print "$fullpath" . PHP_EOL;
      print "---------------------------" . PHP_EOL;
      check($fullpath, $simple, $hunk);
    }
    else if(is_dir($fullpath) && $file != ".." && $file != ".") {
      checkDirectory($fullpath, $simple, $hunk);
    }
  }
}

if(is_file($path) && isPHPFile($path)) {
  check($path);
}
else if(is_dir($path)) {
  checkDirectory($path, $simple, $hunk);}
else {
  die('Not file or directory.');
}
