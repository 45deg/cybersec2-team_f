<?php
namespace VulnChecker;

class ScopedTaintVariableRecord extends TaintVariableRecord {

  private $parent;
  private $return = TAINT_CLEAN; // is it safe?
  private $globals = array();

  public function __construct($parent){
    $this->parent = $parent;
  }

  public function get($name){
    if(isset($this->globals[$name])) {
      // グローバルならどこから呼ばれるのかわからないのでMAYBE
      return TAINT_MAYBE;
    }

    $super_get = parent::get($name); // 親クラス TaintVariableRecord の get
    if(!is_null($super_get)) {
      return $super_get;
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

  public function discardScope(){
    return $this->parent;
  }
}