<?php
namespace VulnChecker;

class ScopedTaintVariableRecord extends TaintVariableRecord {

  private $parent;

  public function __construct($parent){
    $this->parent = $parent;
  }

  public function get($name){
    $super_get = parent::get($name); // 親クラス TaintVariableRecord の get
    if(!is_null($super_get)) {
      return $super_get;
    }
  }

  public function discardScope(){
    return $this->parent;
  }
}