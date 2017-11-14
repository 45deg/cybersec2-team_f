<?php
namespace VulnChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

/* Visitor パターンによる AST の解析 */

class Visitor extends NodeVisitorAbstract
{
  public function leaveNode(Node $node) {
    // nothing to do
  }
}