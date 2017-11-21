<?php
namespace VulnChecker;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeVisitorAbstract;

/* Visitor パターンによる AST の解析 */

class TaintVisitor extends NodeVisitorAbstract
{
  protected $variables;

  public function __construct(){
    $this->variables = new TaintVariableRecord();
  }

  public function enterNode(Node $node){
    if($node instanceof Node\FunctionLike){
      // create scope
      $this->variables = $this->variables->createScope(TaintVariableRecord::SCOPE_FUNCTION);
    } else if($this->isBranch($node)){
      $this->variables = $this->variables->createScope(TaintVariableRecord::SCOPE_BRANCH);
    } else if($this->isLoop($node)){
      $this->variables = $this->variables->createScope(TaintVariableRecord::SCOPE_LOOP);
    }
  }

  public function leaveNode(Node $node) {
    if($node instanceof Node\FunctionLike ||
       $this->isBranch($node) || $this->isLoop($node)){
      // discard scope
      $scope = $this->variables;
      $this->variables = $scope->discardScope();
      // add function definition
      if($node instanceof Stmt\Function_){
        $this->variables->setFunction($node->name, $scope->getFunctionInfo());
      }
    }

    // 文の評価
    if($node instanceof Stmt) {
      if($node instanceof Stmt\Global_) {
        $function = $this->variables->findScope(function($scope){
          return $scope instanceof FunctionTaintVariableRecord;
        });
        assert(isset($function), 'global is placed out of function');
        foreach($node->vars as $var) {
          $function->addGlobal($this->getVarName($var));
        }
      } else if ($node instanceof Stmt\Return_) { 
        $function = $this->variables->findScope(function($scope){
          return $scope instanceof FunctionTaintVariableRecord;
        });
        assert(isset($function), 'return is placed out of function');
        $function->addReturn($node->expr->getAttribute('taint'));
      } else if ($node instanceof Stmt\Continue_ ||
                 $node instanceof Stmt\Break_) {
        // TODO: ラベル付きの場合, switch 中の break の場合
        $loop = $this->variables->findScope(function($scope){
          return $scope instanceof BranchTaintVariableRecord && $scope->isLoop();
        });
        if(!is_null($loop)) {
          $loop->setMask();
        }
      }
    }

    // 式の評価
    if($node instanceof Expr) {
      $tainted = TAINT_MAYBE; // Expr のデフォルト汚染レベル: MAYBE

      if($node instanceof Expr\ArrayDimFetch){
        // 配列アクセス
        $name = $this->getVarName($node);
        $tainted = $this->variables->get($name);
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
          if($node instanceof Expr\AssignOp) {
            // 演算がある場合は持ち上げ
            $this->variables->lift($name, $tainted);
          } else {
            $this->variables->set($name, $tainted);
          }
        }
      } else if($node instanceof Expr\BinaryOp){
        // 二項演算 : 両方チェック
        $tainted = max($node->left->getAttribute('taint'), 
                       $node->right->getAttribute('taint'));
        // 右の項は評価されないかもしれない
        if($node instanceof Expr\BooleanAnd ||
           $node instanceof Expr\BooleanOr){
          $node->right->setAttribute('branch', TRUE);
        }
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
        if(is_null($node->if)) {
          // PHP 5.3 以上だと if を省略できる。
          $tainted = max($node->cond->getAttribute('taint'), 
                         $node->else->getAttribute('taint'));
        } else {
          $tainted = max($node->if->getAttribute('taint'), 
                         $node->else->getAttribute('taint'));
          $node->if->setAttribute('branch', TRUE); // if 式は評価されない場合がある
        }
        $node->else->setAttribute('branch', TRUE); // else 式は評価されない場合がある
      } else if($node instanceof Expr\Variable){
        $tainted = $this->variables->get($node->name);
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
        return TAINT_ESCAPE_CLEAN;
      } else if(!is_null($func = $this->variables->getFunction($name))){
        // 定義済みの関数がある
        foreach($func['globals'] as $name => $taint){
          // グローバルの汚染を伝播
          $this->variables->set($name, $taint);
        }
        return $func['return'];
      } else {
        // TODO
        return TAINT_MAYBE;
      }
    } else if($node->name instanceof Expr) {
      return $node->name->getAttribute('taint');
    }
  }

  private function isBranch(Node $node){
    if($node instanceof Stmt) {
      return $node instanceof Stmt\Catch_ ||
             $node instanceof Stmt\Else_ ||
             $node instanceof Stmt\ElseIf_ ||
             $node instanceof Stmt\Finally_ ||
             $node instanceof Stmt\If_ ||
             $node instanceof Stmt\TryCatch;
    } else if($node instanceof Expr) {
      return $node->getAttribute('branch') === TRUE;
    } else {
      return FALSE;
    }
  }

  private function isLoop(Node $node){
    if($node instanceof Stmt) {
      return $node instanceof Stmt\Do_ ||
             $node instanceof Stmt\For_ ||
             $node instanceof Stmt\Foreach_ ||
             $node instanceof Stmt\While_ ||
             $node instanceof Stmt\Switch_ ; // workaround
    } else {
      return FALSE;
    }
  }
}