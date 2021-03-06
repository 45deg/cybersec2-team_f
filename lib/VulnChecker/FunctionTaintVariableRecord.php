<?php
namespace VulnChecker;

class FunctionTaintVariableRecord extends ScopedTaintVariableRecord {

  private $return = TAINT_CLEAN; // is it safe?
  private $globals = array();

  public function get($name, $default = TAINT_MAYBE){
    if(isset($this->globals[$name])) {
      // グローバルならどこから呼ばれるのかわからないのでMAYBE
      return TAINT_MAYBE;
    } else {
      return parent::get($name, $default); // 親クラス TaintVariableRecord の get
    }
  }

  public function set($name, $type){
    parent::set($name, $type);
    if(isset($this->globals[$name])) {
      // グローバルにあるなら影響を伝播
      $this->globals[$name] = $type;
    }
  }

  public function addReturn($val){
    $this->return = max($this->return, $val);
  }

  public function addGlobal($val){
    // グローバルに登録、デフォルトがCLEAN
    $this->globals[$val] = TAINT_CLEAN;
  }

  public function getFunctionInfo(){
    return array('return' => $this->return,
                 'globals' => $this->globals);
  }
}