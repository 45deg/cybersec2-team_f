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
      $tainted = $this->getTainted($node->expr);
      if($tainted > TAINT_CLEAN) {
        $this->notice($node, "eval is called!", $tainted);
      }
    }
    /* require / include * */
    if($node instanceof Node\Expr\Include_) {
      $tainted = $this->getTainted($node->expr);
      if($tainted > TAINT_CLEAN) {
        $this->notice($node, "include or require is called!", $tainted);
      }
    }
    /* 関数呼び出し */
    else if($node instanceof Node\Expr\FuncCall) {
      $this->checkFuncCall($node);
    }
    /* Backtick */
    else if($node instanceof Node\Expr\ShellExec) {
      $tainted = $this->getArrayTainted($node->parts);
      if($tainted > TAINT_ESCAPE_CLEAN) {
        $this->notice($node, "Backtick is used!", $tainted);
      }
    }

  }

  private $execFunc = array(
    "exec"        => array(0), // 確認する引数のインデックス
    "shell_exec"  => array(0),
    "passthru"    => array(0),
    "system"      => array(0),
    "popen"       => array(0),      
    "pcntl_exec"  => array(0, 1),
    "proc_open"   => array(0)
  );

  private $evalFunc = array(
    "preg_replace"    => array(1), // 0番目がeのときのみ
    "create_function" => array(1)
  );

  // TODO: もうちょっとまともに
  private function notice(Node $node, $message, $level) {
    print "[{$node->getAttribute('startLine')}:{$node->getAttribute('startTokenPos')}]";
    print "<$level> $message";
    print "\n";
  }

  private function getTainted(Node $node) {
    $tainted = $node->getAttribute('taint');
    return is_null($tainted) ? TAINT_CLEAN : $tainted;
  }

  private function getArgumentsTainted(array $args, array $indices) {
    $func = function($index) use($indices) {
      return in_array($index, $indices);
    };
    $func2 = function($arg) {
      return $arg->value;
    };
    $arr = array_filter($args, $func, ARRAY_FILTER_USE_KEY);
    $arr2 = array_map($func2, $arr);
    return $this->getArrayTainted($arr2);
  }

  private function getArrayTainted(array $arr) {
    $func = function($node) {
      return $this->getTainted($node);
    };
    return max(array_map($func, $arr));
  }

  private function checkFuncCall(Node $node) {
    $name = $node->name;
    if($name instanceof Node\Name) {
      $funcName = $name->parts[0];
      if(array_key_exists($funcName, $this->execFunc)) {
        $tainted = $this->getArgumentsTainted($node->args, $this->execFunc[$funcName]);  
        if($tainted > TAINT_ESCAPE_CLEAN) {
          $this->notice($node, "$funcName is called!", $tainted);
        }
      } else if(array_key_exists($funcName, $this->evalFunc)) {
        // TODO: preg_replace eオプションの考慮
        $tainted = $this->getArgumentsTainted($node->args, $this->evalFunc[$funcName]);  
        if($tainted > TAINT_CLEAN) {
          $this->notice($node, "$funcName (eval) is called!", $tainted);
        }
      }
    } 
    else if($name instanceof Node\Expr\Variable) {
      // TODO?
    }
    else if($name instanceof Node\Expr\ArrayDimFetch) {
      // TODO?
    }
    else {
      var_dump($name);
    }

  }


}