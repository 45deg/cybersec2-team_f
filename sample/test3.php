<?php

// 汚染解析のチェック
function somefunc(){
  $a = "safe";
  return $a;
}

$a = $_GET['po'];
$b = "safe";
$c = $a . $b;

$d = escapeshellarg($a);
$e = '';
$e .= $d;
$f = $e;
$f .= $a;

$g = $_GET['so'] . $_POST['no'];

$h = somefunc();

$i = $j = "hi";

$l = array();
$l['no'] = 1;

$m = "{$_GET['la']} $e";
$n = "$i $j";
$o = CONST_VALUE;