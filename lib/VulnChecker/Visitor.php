<?php
namespace VulnChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

/* Visitor パターンによる AST の解析 */

class Visitor extends NodeVisitorAbstract
{
  public function leaveNode(Node $node) {
    /* eval の場合 */
    if($node instanceof Node\Expr\Eval_) {
      // TODO: 引数 ($node->expr) が安全 (定数やサニタイズ済) だった場合はOKにする。
      $is_safe = false;
      if(!$is_safe) {
        // TODO: 警告機構をモジュール化する
        print "[{$node->getAttribute('startLine')}:{$node->getAttribute('startTokenPos')}]";
        print " eval is called!";
      }
    }

    /* 関数呼び出し */
    if($node instanceof Node\Expr\FuncCall) {
      var_dump($node->name->parts[0]);
    }
  }
}