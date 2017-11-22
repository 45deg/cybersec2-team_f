<?php
namespace VulnChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

/* Visitor パターンによる AST の解析 */

class Visitor extends NodeVisitorAbstract
{

  private $positionStore;

  public function __construct(PositionStore $position, $noticeSimple=TRUE, $noticeHunk=3){
    $this->positionStore = $position;
    $this->noticeSimple = $noticeSimple;
    $this->noticeHunk = $noticeHunk;
  }
  
  public function leaveNode(Node $node) {
    /* eval の場合 */
    if($node instanceof Node\Expr\Eval_) {
      $tainted = $this->getTainted($node->expr);
      if($tainted > TAINT_CLEAN) {
        $this->notice($node, "eval is called!", $tainted);
      }
    }
    /* require / include * */
    else if($node instanceof Node\Expr\Include_) {
      $tainted = $this->getTainted($node->expr);
      if($tainted > TAINT_CLEAN) {
        $name = $this->includeType[$node->type];
        $this->notice($node, "$name is called!", $tainted);
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
    "preg_replace"    => array(1, 2), // 0番目がeのときのみ
    "create_function" => array(1),
    "assert"          => array(0),
    "unserialize"     => array(0)
  );

  private $includeType = array(
    1 => 'include',
    2 => 'include_once',
    3 => 'require',
    4 => 'require_once'
  );

  // TODO: もうちょっとまともに
  private function notice(Node $node, $message, $level) {
    $line = $node->getAttribute('startLine');
    $column = $this->positionStore->getColumn($line, $node->getAttribute('startFilePos'));
    $level_str = (string)$level;
    if($level == TAINT_DITRY) {
      $level_str = "DANGER";
      print "\033[1;31m";
    } else if($level == TAINT_MAYBE) {
      $level_str = "WARNING";
      print "\033[1;33m";
    }
    print "[{$line}:{$column}]";
    print " ($level_str) $message";
    
    if(!$this->noticeSimple) {
      print "\033[90m\n";
      $hunk = $this->noticeHunk;
      $start = max((int)$line - $hunk, 1);
      $end = (int)$line + $hunk;
      $pad = strlen($end + 1);
      for($no = $start; $no <= $end; $no++) {
        $raw = $this->positionStore->getLine($no);
        if(!isset($raw)) break;
        $no = str_pad($no, $pad, " ", STR_PAD_LEFT);
        if($no == $line) print "\033[0;32m";
        print "$no | $raw\n";
        if($no == $line) print "\033[90m";
      }
    }
    print "\033[0m\n";
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

  // 雑
  private function lastString($node) {
    if($node instanceof Node\Scalar\String_) {
      return $node->value;
    }
    else if($node instanceof Node\Expr\BinaryOp) {
      return $this->lastString($node->right);
    }
    else if($node instanceof Node\Scalar\Encapsed) {
      $arr = $node->parts;
      $last = end($arr);
      if($last instanceof Node\Scalar\EncapsedStringPart) {
        return $last->value;
      }
      if($this->getTainted($last) > TAINT_CLEAN) {
        return "/e";
      }
    }
    if($this->getTainted($node) > TAINT_CLEAN) {
      return "/e";
    }
    return "/ok";
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
        if($funcName == "preg_replace") {
          $temp = $this->lastString($node->args[0]->value);
          $arr = explode('/', $temp);
          $last = end($arr);
          if(!strstr($last, 'e')) {
            //print 'preg_replace:: SAFE!' . PHP_EOL;
            return;
          } else {
            //print "preg_replace:: GYAAAAAA" . PHP_EOL;
          }
        }
        $tainted = $this->getArgumentsTainted($node->args, $this->evalFunc[$funcName]);  
        if($tainted > TAINT_CLEAN) {
          $this->notice($node, "$funcName (eval) is called!", $tainted);
        }
      }
    } 
    else if($name instanceof Node\Expr\Variable) {
      $tainted = $this->getTainted($name);  
      if($tainted > TAINT_CLEAN) {
        if(is_string($name->name)){
          $this->notice($name, "function \${$name->name} is tainted!", $tainted);
        } else {
          $this->notice($name, "tainted function is called!", $tainted);
        }
      }
    }
    else if($name instanceof Node\Expr\ArrayDimFetch) {
      $target = $name->var;
      $tainted = $this->getTainted($target);  
      if($tainted > TAINT_CLEAN) {
        $this->notice($name, "function \${$target->name}[] is tainted!", $tainted);
      }
    }
    else {
      // var_dump($name);
    }

  }


}