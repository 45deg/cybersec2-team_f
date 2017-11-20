<?php
namespace VulnChecker;

class BranchTaintVariableRecord extends ScopedTaintVariableRecord {

  private $is_loop; // is it in loop (while, for, foreach ...)?

  public function __construct($parent, $is_loop){
    parent::__construct($parent);
    $this->is_loop = $is_loop;
  }

  public function get($name, $default = TAINT_MAYBE){
    $in_scope = parent::get($name, NULL);
    if(!is_null($in_scope)){
      return $in_scope;
    } else if(!$this->is_loop) {
      // (ループ内部以外の時は) 外側の変数を参照
      // ループ内部だと後の式で taint される可能性があるため
      return $this->parent->get($name, $default);
    } else {
      return $default;
    }
  }

  public function set($name, $type){
    parent::set($name, $type);
  }

  public function discardScope(){
    foreach($this->vars as $var => $taint) {
      $this->parent->lift($var, $taint);
    }
    return $this->parent;
  }
}