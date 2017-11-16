<?php
namespace VulnChecker;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeVisitorAbstract;

/* Visitor パターンによる AST の解析 */

class TaintVisitor extends NodeVisitorAbstract
{
  protected $variables;

  public function __construct(){
    $this->variables = TaintVariableRecord::createGlobalRecord();
  }

  public function enterNode(Node $node){
    if($node instanceof Node\FunctionLike){
      // create scope
      $this->variables = new TaintVariableRecord($this->variables);
    }
  }

  public function leaveNode(Node $node) {
    if($node instanceof Node\FunctionLike){
      // discard scope
      $this->variables = $this->variables->getParent();
    } else if($node instanceof Expr) {
      $tainted = TAINT_MAYBE; // Expr のデフォルト汚染レベル: MAYBE

      if($node instanceof Expr\Assign || $node instanceof Expr\AssignOp){
        // 代入式
        $name = $this->getVarName($node->var);
        if(isset($name)) {
          $tainted = $node->expr->getAttribute('taint');
          if($node instanceof Expr\AssignOp) { // AssignOp の場合 変数自身の汚染も考慮
            $tainted = max($tainted, $this->variables->getOrElse($name, TAINT_MAYBE));
          }
          $this->variables->set($name, $tainted);
        }
      } else if($node instanceof Expr\Variable){
        $tainted = $this->variables->getOrElse($node->name, TAINT_MAYBE);
      } else if($node instanceof Node\Scalar) {
        // スカラー値
        if($node instanceof Node\Scalar\Encapsed) {
          // 変数展開 : propagate
          $tainted = TAINT_CLEAN;
          foreach($node->parts as $part){
            $tainted = max($part->getAttribute('taint'), $tainted);
          }
        } else {
          $tainted = TAINT_CLEAN;
        } 
      }

      $node->setAttribute('taint', $tainted);
    }
  }

  public function afterTraverse(array $nodes){
    var_dump($nodes);
    var_dump($this->variables);
  }

  public function getVarName(Node $lvalue){
    if($lvalue instanceof Expr\Variable) {
      // Variable(v) => v
      return $lvalue->name;
    } else if(isset($lvalue->var) && $lvalue->var instanceof Expr\Variable){
      // ArrayDim(v, k) => v
      return $lvalue->var->name;
    } else {
      // _ => null
      return NULL;
    }
  }
}