<?php

/* ライブラリ読み込み */
require_once "vendor/autoload.php";
require_once "lib/bootstrap.php";

/* ファイル読み込み */
$path = $argv[1];
if(!isset($path)) die('Input a file.');


function check($filename) {

$code = file_get_contents($filename);
if($code === FALSE) {
  die('Cannot load a file ' . $filename);
}

$position = new VulnChecker\PositionStore($code);

$traverser = new PhpParser\NodeTraverser;
$traverser->addVisitor(new VulnChecker\TaintVisitor);
$traverser->addVisitor(new VulnChecker\Visitor($position));

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
  die("Parse error: {$error->getMessage()}");
}

}

function isPHPFile($filename) {
  $ext = substr($filename, strrpos($filename, '.') + 1);
  return $ext == "php";
}

function checkDirectory($path) {
  $files = scandir($path);
  foreach($files as $file) {
    $fullpath = "$path/$file";
    if(is_file($fullpath) && isPHPFile($file)) {
      print "===========================" . PHP_EOL;
      print "$fullpath" . PHP_EOL;
      print "---------------------------" . PHP_EOL;
      check($fullpath);
    }
    else if(is_dir($fullpath) && $file != ".." && $file != ".") {
      checkDirectory($fullpath);
    }
  }
}

if(is_file($path) && isPHPFile($file)) {
  print "===========================" . PHP_EOL;
  print "$path" . PHP_EOL;
  print "---------------------------" . PHP_EOL;
  check($path);
}
else if(is_dir($path)) {
  checkDirectory($path);}
else {
  die('Unknown input.');
}
