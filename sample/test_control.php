<?php
// test 1
$a = $_GET['dirty'];
$a = "echo" . escapeshellarg($a);
system($a);

// test 2
if($_GET['a'] > 0) {
  $b = $_GET['dirty'];
} else {
  $b = 'echo clean';
}
system($b);

// test 3
$cond ? ($no = 'clean') : ($no = $_GET['dirty']);
system($no);

// test 3.1
system(($no = $_GET['dirty']) ?: ($no = 'clean'));

// test 4
$c = 'echo safe';
while($cond) {
   system($c);
   $c = $_GET['unsafe'];
}
system($c);

// test 5
while($cond) {
  $d = $_GET['unsafe'];
  if($po) break;
  $d = 'echo clean';
}
system($d);

// test 7
try {
  $e = $_GET['unsafe'];
} catch(Exception $e_) {
  $e = 'echo clean';
}
system($e);

// test 8
try {
  $f = 'echo clean';
} catch(Exception $e) {
  $f = $_GET['unsafe'];
}
system($f);

// test 9
if($pa === 1) {
  if($pi === 4) $c = $_GET['po'];
  if($e) $f = $c . $d;
  else $f = 'clean';
  system($f);
  for($i = 0; $i < 10; $i++) {
    if($i == 3) break;
    $na = 'clean'; // ← 上に break があるため $na は秘匿される
    system($f);
  } 
  system($na); // <Lv10> になるはず
}
system($c);