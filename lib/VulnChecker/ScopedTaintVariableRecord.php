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

  public function getParent(){
    return $this->parent;
  }
}