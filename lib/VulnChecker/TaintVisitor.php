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
    } else if ($node instanceof Expr\Assign){
      // 代入式
      $name = $this->getVarName($node->var);
      if(isset($name)) {
        $tainted = $node->expr->getAttribute('taint');
        if(!isset($tainted)) $tainted = TAINT_MAYBE;
        $this->variables->set($name, $tainted);
        $node->setAttribute('taint', $tainted); // propergate
      } else {
        $node->setAttribute('taint', TAINT_MAYBE); // propergate
      }
    } else if($node instanceof Node\Scalar) {
      // スカラー値
      if($node instanceof Node\Scalar\Encapsed) {
        // 変数展開 : propagate
        $taint = TAINT_CLEAN;
        foreach($node->parts as $part){
          $taint = max($part->getAttribute('taint'), $taint);
        }
        $node->setAttribute('taint', $taint);
      } else {
        // それ以外(文字列、数値等) : CLEAN
        $node->setAttribute('taint', TAINT_CLEAN);
      } 
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