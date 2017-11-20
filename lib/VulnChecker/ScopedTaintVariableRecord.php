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

  public function findScopeOf($classname){
    if(get_class($this) === $classname) {
      return $this;
    } else if($this->parent instanceof ScopedTaintVariableRecord) {
      return $this->parent->findScopeOf($classname);
    } else {
      return NULL;
    }
  }
}