<?php

function clean_func(){
  return 'echo clean';
}

function partial_dirty(){
  if($_GET['x'] > 1){
    return $_GET['x'];
  } else {
    return 'clean';
  }
}

function get_func($name){
  return $_GET[$name];
}

function destroy_c(){
  global $c;
  $c = $_GET['hehehe'];
}

$a = get_func('hoge');
system($a); // BAD

$b = clean_func();
system($b); // OK

system(partial_dirty()); // BAD

$c = 'clean!?';
destroy_c();
system($c); // BAD

/* // TODO
$closure = function(){
  $b = $_GET['a'];
};

system($closure());
system($b);
*/
