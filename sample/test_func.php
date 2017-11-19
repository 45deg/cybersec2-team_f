<?php

function clean_func(){
  return 'echo clean';
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