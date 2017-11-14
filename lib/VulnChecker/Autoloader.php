<?php
namespace VulnChecker;

/* 自動ファイルローダー */

class Autoloader
{
    private static $registered = false;
    static public function register($prepend = false) {
        if (self::$registered === true) {
            return;
        }
        spl_autoload_register([__CLASS__, 'autoload'], true, $prepend);
        self::$registered = true;
    }

    static public function autoload($class) {
        if (0 === strpos($class, 'VulnChecker\\')) {
            $fileName = __DIR__ . strtr(substr($class, 11), '\\', '/') . '.php';
            if (file_exists($fileName)) {
                require $fileName;
            }
        }
    }
}