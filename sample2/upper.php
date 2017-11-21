<html>
<head></head>
<body><img src="./img/upper.png" width="1024" alt="image">
<form action="upper.php" method="GET">
  text: <input type="text" name="text" value="" placeholder="hello world">
  <p>
  target: <input type="text" name="target" value="" placeholder="world">
  <p>
  <select name="method">
  <option value="strtoupper">strtoupper</option>
  <option value="strtolower">strtolower</option>
  </select>
  <p>
  <input type="submit" value="submit">
</form>
</body>
</html>
<?php
/* 組み込み簡易サーバー */
// php -t sample2 -S localhost:8081
// localhost:8081/upper.php?text=cyber+security&target=cyber&method=strtoupper
// localhost:8081/upper.php?text=ls&target=ls&method=shell_exec


if(isset($_GET['text']) && 
   isset($_GET['target']) && 
   isset($_GET['method'])) {

  $text = $_GET['text'];
  $target = $_GET['target'];
  $method = $_GET['method'];
  $result = preg_replace("/($target)/e", "$method('\$1')", $text);
  
  print '<br>';
  print htmlspecialchars($text);
  print ' => ';
  print $result; 
}
  