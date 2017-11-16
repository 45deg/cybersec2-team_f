<?php

/* ライブラリ読み込み */
require_once "vendor/autoload.php";
require_once "lib/bootstrap.php";

/* ファイル読み込み */
$filename = $argv[1];
if(!isset($filename)) die('Input a file.');

$traverser = new PhpParser\NodeTraverser;
$traverser->addVisitor(new VulnChecker\TaintVisitor);
$traverser->addVisitor(new VulnChecker\Visitor);

/* パース */
$lexer = new PhpParser\Lexer(array(
  'usedAttributes' => array('startLine', 'startTokenPos')
));
$parser = (new PhpParser\ParserFactory)->create(
                PhpParser\ParserFactory::PREFER_PHP5, $lexer);
try {
  $code = file_get_contents($filename);
  $ast = $parser->parse($code);
  $traverser->traverse($ast);
} catch (Error $error) {
  die("Parse error: {$error->getMessage()}");
}
