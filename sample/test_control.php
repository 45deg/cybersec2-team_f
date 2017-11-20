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
system($cond ? $_GET['dirty'] : $clean);

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
  break;
  $d = 'echo clean';
}
system($d);