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
  protected $vars = array();
  protected $functions = array();

  const TAINTED_SUPER_GLOBALS = array(
    '_GET', '_SET', '_REQUEST', '_COOKIE', '_FILES', 'argv'
  );

  public function set($name, $type){
    $this->vars[$name] = $type;
  }

  public function get($name){
    if(in_array($name, self::TAINTED_SUPER_GLOBALS)) {
      return TAINT_DITRY;
    } else if(isset($this->vars[$name])){
      return $this->vars[$name];
    } else {
      return NULL;
    }
  }

  public function getOrElse($name, $default){
    $v = $this->get($name);
    return isset($v) ? $v : $default;
  }

  public function createScope(){
    return new ScopedTaintVariableRecord($this);
  }
}