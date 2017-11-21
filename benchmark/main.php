<?php

require_once __DIR__ . "/../vendor/autoload.php";

print "file,count,time\n";
foreach(glob(__DIR__ . '/targets/*.php') as $filename){
  $nodes = getNumberOfNodes($filename);
  if($nodes === NULL) continue;
  $time_res = shell_exec("(time php " . __DIR__ . "/../main.php " . $filename . ") 2>&1");
  preg_match('/user\t([0-9]+)m([0-9\\.]+)s/', $time_res, $matches);
  $time = (float)$matches[1]*60 + (float)$matches[2];
  print "\"" . basename($filename) . "\"," . $nodes . "," . ($time * 1000) . "\n";
}

function getNumberOfNodes($filename){
  // Calcurate the number of nodes
  $code = file_get_contents($filename);

  $traverser = new PhpParser\NodeTraverser;
  $counter = new class extends PhpParser\NodeVisitorAbstract {
    public $number = 0;
    public function enterNode(PhpParser\Node $node) {
      $this->number += 1;
    }
  };
  $traverser->addVisitor($counter);
  
  $parser = (new PhpParser\ParserFactory)->create(PhpParser\ParserFactory::PREFER_PHP5);
  try {
    $ast = $parser->parse($code);
    $traverser->traverse($ast);
    return $counter->number;
  } catch (PhpParser\Error $error) {
    return NULL;
  }
}

