<?php
namespace VulnChecker;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeVisitorAbstract;

/* Visitor パターンによる AST の解析 */

class TaintVisitor extends NodeVisitorAbstract
{
  private $global_vars = array();
  private $scope = NULL;

  public function leaveNode(Node $node) {
    if($node instanceof Expr\Assign) {
      var_dump($node->var);
      print ' = ';
      var_dump($node->expr);
    }
  }
}