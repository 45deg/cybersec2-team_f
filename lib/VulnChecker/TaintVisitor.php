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

      if($node instanceof Expr\ArrayDimFetch){
        // 配列アクセス
        $name = $this->getVarName($node);
        $top_name = explode('$', $name)[0];
        $tainted = $this->variables->getOrElse($top_name
                      ,$this->variables->getOrElse($name,TAINT_MAYBE));
      } else if($node instanceof Expr\ArrayItem) {
        $tainted = $node->value->getAttribute('taint');
      } else if($node instanceof Expr\Assign || 
                $node instanceof Expr\AssignOp ||
                $node instanceof Expr\AssignRef ){
        // 代入式
        $name = $this->getVarName($node->var);
        // 変数名が取れる && ? が含まれていない場合 (配列アクセスに変数を用いていない場合)
        if(isset($name) && strpos($name, '?') === FALSE) {
          $tainted = $node->expr->getAttribute('taint');
          // すでに変数が定義されている場合は汚染を伝播させる
          // TODO: この場合 $a = $_GET['po']; $a = 1; のような変数の再代入に対応できない。
          // なお、演算代入の場合はデフォルトが MAYBE 
          $tainted = max($tainted, $this->variables->getOrElse($name, 
                  ($node instanceof Expr\AssignOp) ? TAINT_MAYBE : TAINT_CLEAN));
          $this->variables->set($name, $tainted);
        }
      } else if($node instanceof Expr\BinaryOp){
        // 二項演算 : 両方チェック
        $tainted = max($node->left->getAttribute('taint'), 
                       $node->right->getAttribute('taint'));
      } else if($node instanceof Expr\Cast || 
                $node instanceof Expr\Clone_ ||
                $node instanceof Expr\ErrorSuppress){
        $tainted = $node->expr->getAttribute('taint');
      } else if($node instanceof Expr\Eval_ || 
                $node instanceof Expr\ShellExec){
        $tainted = TAINT_DIRTY;
      } else if($node instanceof Expr\FuncCall){
        $tainted = $this->analyzeFunctionCall($node);
      } else if($node instanceof Expr\Ternary){
        // 三項演算 : 両方チェック
        $tainted = max($node->if->getAttribute('taint'), 
                       $node->else->getAttribute('taint'));
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

      // おそらく安全だと思われるもの
      else if( $node instanceof Expr\BitwiseNot || $node instanceof Expr\BooleanNot
            || $node instanceof Expr\Closure || $node instanceof Expr\Empty_
            || $node instanceof Expr\Exit_ || $node instanceof Expr\Instanceof_
            || $node instanceof Expr\Isset_ || $node instanceof Expr\New_
            || $node instanceof Expr\PostInc || $node instanceof Expr\PostDec
            || $node instanceof Expr\PreInc || $node instanceof Expr\PreDec 
            || $node instanceof Expr\Print_ || $node instanceof Expr\UnaryMinus
            || $node instanceof Expr\UnaryPlus ) {
        $tainted = TAINT_CLEAN;
      }

      /* 定数の扱いについてはTODO → 今は全部 MAYBE 
         他の保留: Array_, List_, MethodCall, PropertyFetch, 
                  StaticCall, StaticPropertyFetch, Yield*
      */

      $node->setAttribute('taint', $tainted);
    }
  }

  /*
  public function afterTraverse(array $nodes){
    var_dump($nodes);
    var_dump($this->variables);
  }
  */

  private function getVarName(Node $lvalue){
    if($lvalue instanceof Expr\Variable) {
      // Variable(v) => v
      return $lvalue->name;
    } else if($lvalue instanceof Expr\ArrayDimFetch){
      // ArrayDim(v, k) => (getVarName v):k
      $var_name = $this->getVarName($lvalue->var);
      if(is_null($var_name)) return NULL;
      if($lvalue->dim instanceof Node\Scalar\String_ ||
         $lvalue->dim instanceof Node\Scalar\LNumber ) {
        $var_key = str_replace('$', '_DOLLAR_', $lvalue->dim->value);
      } else {
        $var_key = '?';
      }
      return $var_name . '$' . $var_key;
    } else {
      // _ => null
      return NULL;
    }
  }

  private function analyzeFunctionCall(Expr\FuncCall $node){
    if($node->name instanceof Node\Name) {
      $name = $node->name->toString();
      if($name === 'escapeshellarg' || $name === 'escapeshellcmd'){
        return TAINT_CLEAN;
      } else {
        // TODO
        return TAINT_MAYBE;
      }
    } else if($node->name instanceof Expr) {
      return $node->name->getAttribute('taint');
    }
  }
}