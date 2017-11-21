<html>
<head>
<style type="text/css">
pre {
  font-family: Consolas, 'Courier New', Courier, Monaco, monospace;
  font-size: 12px;
  line-height: 1.2;
}  
</style>
</head>
<body>
<form action="banner.php" method="GET">
  <input type="text" name="text" value="">
  <p>
  <input type="submit" value="submit">
</form>
</body>
</html>
<?php
/* 組み込み簡易サーバー */
// php -t sample2 -S localhost:8081
// localhost:8081/banner.php?text=cyber
// localhost:8081/banner.php?text=%3B+echo+HACK

$text = "?";
if(isset($_GET['text'])) {
  $text = trim($_GET['text']);
  if(strlen($text) < 1) $text = "?";
}
$aa = shell_exec("banner -w 50 ." . $text);     // MAYBE
print '<pre>';
print preg_replace('/(\r*\n)/i', '<br>', $aa);  // SAFE
print '</pre>';
