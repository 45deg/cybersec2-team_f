<?php
namespace VulnChecker;

class PositionStore {
  private $offsets;
  private $code;

  public function __construct($code){
    $this->code = $code;
    $this->offsets = $this->analyzeOffsets();
  }

  private function analyzeOffsets(){
    $o = 0;
    $line = 1;
    $offsets = array(1 => 0);
    while(($pos = strpos($this->code, "\n", $o)) !== FALSE){
      $line++;
      $o = $pos + 1;
      $offsets[$line] = $o;
    }
    return $offsets;
  }

  public function getColumn($line, $position){
    return $position - $this->offsets[$line] + 1;
  }

  public function getLine($number){
    $start = $this->offsets[$number];
    if(isset($this->offsets[$number + 1])) {
      $length = $this->offsets[$number + 1] - $start;
      return rtrim(substr($this->code, $start, $length));
    } else {
      return rtrim(substr($this->code, $start));
    }
  }
}