# Remote Code Execution Detector

## インストール

```
curl -sS https://getcomposer.org/installer | php
php composer.phar install
```

## 実行

```
php main.php sample/test1.php

# ディレクトリ指定
php main.php sample

# コード片行数指定
php main.php -n2 -fsample 
# シンプル表示
php main.php -s -fsample 
```