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
        print "\n";
      }
    }
    /* require / include * */
    if($node instanceof Node\Expr\Include_) {
      // TODO: 引数 ($node->expr) が安全 (定数やサニタイズ済) だった場合はOKにする。
      $is_safe = false;
      if(!$is_safe) {
        // TODO: 警告機構をモジュール化する
        print "[{$node->getAttribute('startLine')}:{$node->getAttribute('startTokenPos')}]";
        print " include or require is called!";
        print "\n";
      }
    }
    /* 関数呼び出し */
    else if($node instanceof Node\Expr\FuncCall) {
      $this->checkFuncCall($node);
    }
    /* Backtick */
    else if($node instanceof Node\Expr\ShellExec) {
      //$node->parts;
      //var_dump($node);
      print "[{$node->getAttribute('startLine')}:{$node->getAttribute('startTokenPos')}]";
      print " Backtick is used!";
      print "\n";
    }


  }

  // TODO: exec系とeval系で安全な引数かどうか判断基準が変わりそうなので、分けたほうが良さそう
  private $execFunc = array(
    // exec系
    "exec",
    "shell_exec",
    "passthru",
    "system",
    "popen",
    "pcntl_exec",
    "proc_open",
    // eval系
    "preg_replace",
    "create_function"
  );

  private function checkFuncCall(Node $node) {
    $name = $node->name;
    if($name instanceof Node\Name) {
      $funcName = $name->parts[0];
      if(in_array($funcName, $this->execFunc)) {
        // TODO: 引数の解析
        print "[{$node->getAttribute('startLine')}:{$node->getAttribute('startTokenPos')}]";
        print " {$funcName} is called!";
        print "\n";
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