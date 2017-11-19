<?php
namespace VulnChecker;

// 汚染レベル
// DIRTY 危険、$_GET などを直接用いている
const TAINT_DITRY = 20;
// MAYBE 外部関数呼び出しの返り値や解決できない変数などを用いている
const TAINT_MAYBE = 10; 
// CLEAN_ESACPE shellescape を施している
const TAINT_ESCAPE_CLEAN = 1;
// CLEAN 文字列リテラル等
const TAINT_CLEAN = 0;

class TaintVariableRecord
{
  private $vars = array();
  private $parent;

  public function __construct($parent = NULL){
    $this->parent = $parent;
  }

  public function set($name, $type){
    $this->vars[$name] = $type;
  }

  public function get($name){
    if(isset($this->vars[$name])){
      return $this->vars[$name];
    } else if(isset($parent)) {
      return $this->parent->get($name);
    }
  }

  public function getOrElse($name, $default){
    $v = $this->get($name);
    return isset($v) ? $v : $default;
  }

  public static function createGlobalRecord(){
    $ret = new TaintVariableRecord();
    $taint_vars =  array(
      '_GET', '_SET', '_REQUEST', '_COOKIE', '_FILES', 'argv'
    );
    foreach($taint_vars as $v) {
      $ret->set($v, TAINT_DITRY);
    }
    return $ret;
  }

  public function createScope(){
    return new TaintVariableRecord($this);
  }

  public function discardScope(){
    return $this->parent;
  }
}