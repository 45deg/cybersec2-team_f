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
      if($tainted > TAINT_ESCAPE_CLEAN) {
        $this->notice($node, "eval is called!", $tainted);
      }
    }
    /* require / include * */
    if($node instanceof Node\Expr\Include_) {
      $tainted = $this->getTainted($node->expr);
      if($tainted > TAINT_ESCAPE_CLEAN) {
        $this->notice($node, "include or require is called!", $tainted);
      }
    }
    /* 関数呼び出し */
    else if($node instanceof Node\Expr\FuncCall) {
      $this->checkFuncCall($node);
    }
    /* Backtick */
    else if($node instanceof Node\Expr\ShellExec) {
      $tainted = $this->getPartsTainted($node->parts);
      if($tainted > TAINT_ESCAPE_CLEAN) {
        $this->notice($node, "Backtick is used!", $tainted);
      }
    }

  }

  private $execFunc = array(
    "exec",       // 確認する引数: 1番目
    "shell_exec", // 1
    "passthru",   // 1
    "system",     // 1
    "popen",      // 1
    "pcntl_exec", // 1, 2
    "proc_open"   // 1
  );

  private $evalFunc = array(
    "preg_replace",   // 確認する引数: 2番目 (1番目がeのときのみ)
    "create_function" // 2
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

  private function getPartsTainted(array $parts) {
    $func = function($node) {
      return $this->getTainted($node);
    };
    return max(array_map($func, $parts));
  }

  private function checkFuncCall(Node $node) {
    $name = $node->name;
    if($name instanceof Node\Name) {
      $funcName = $name->parts[0];
      // 何番目の引数を見るかは関数によって変わるかも
      // とりあえず1番目
      $tainted = $this->getTainted($node->args[0]->value);
      
      if(in_array($funcName, $this->execFunc)) {
        // 引数解析
        if($tainted > TAINT_ESCAPE_CLEAN) {
          $this->notice($node, "$funcName is called!", $tainted);
        }
      } else if(in_array($funcName, $this->evalFunc)) {
        if($tainted > TAINT_ESCAPE_CLEAN) {
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