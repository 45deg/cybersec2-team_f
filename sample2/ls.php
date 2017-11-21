<html>
<head></head>
<body>
<form action="ls.php" method="GET">
  filter: <input type="text" name="text" value="">
  <p>
  <input type="submit" value="submit">
</form>
</body>
</html>
<?php
/* 組み込み簡易サーバー */
// php -t sample2 -S localhost:8081
// localhost:8081/ls.php?text=php
// localhost:8081/ls.php?text=php+%7C+xargs+cat+

$text = "";
if(isset($_GET['text'])) {
  $text = $_GET['text'];
  print 'filter: ' . htmlspecialchars($text) . '<br>';
}
print '<hr>';
$cmd = strlen($text) > 0 ? " | grep ${text}" : "";
$files = `ls $cmd`;
print preg_replace('/[\n\r\t]/', '<br>', $files);
