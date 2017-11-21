<?php
namespace VulnChecker;

abstract class ScopedTaintVariableRecord extends TaintVariableRecord {

  protected $parent;

  public function __construct($parent){
    $this->parent = $parent;
  }

  public function discardScope(){
    return $this->parent;
  }

  public function findScope($pred){
    if($pred($this)) {
      return $this;
    } else if($this->parent instanceof ScopedTaintVariableRecord) {
      return $this->parent->findScope($pred);
    } else {
      return NULL;
    }
  }
}