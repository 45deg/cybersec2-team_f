<?php

$code = $_GET["code"];

print eval($code);
print eval('print ' . '"hoge";');