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

  public function lift($name, $type, $default = TAINT_CLEAN){
    $this->set($name, max($type, $this->get($name, $default)));
  }

  public function get($name, $default = TAINT_MAYBE){
    $top = substr($name, 0, strpos($name, '$'));
    if(in_array($top, self::TAINTED_SUPER_GLOBALS)) {
      return TAINT_DITRY;
    } else if(isset($this->vars[$name])){
      return $this->vars[$name];
    } else {
      return $default;
    }
  }

  public function getFunction($name){
    return $this->functions[$name];
  }

  public function setFunction($name, $type){
    $this->functions[$name] = $type;
  }

  const SCOPE_FUNCTION = 1;
  const SCOPE_BRANCH = 2;
  const SCOPE_LOOP = 3;

  public function createScope($type){
    if($type === self::SCOPE_FUNCTION) {
      return new FunctionTaintVariableRecord($this);
    } else if($type === self::SCOPE_BRANCH) {
      return new BranchTaintVariableRecord($this, FALSE);
    } else if($type === self::SCOPE_LOOP) {
      return new BranchTaintVariableRecord($this, TRUE);
    }
  }

  public function findScope($pred){
    return NULL;
  }
}