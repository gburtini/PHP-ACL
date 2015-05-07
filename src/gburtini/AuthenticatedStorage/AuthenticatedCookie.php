<?php
namespace gburtini\AuthenticatedStorage;

require_once dirname(__FILE__) . "/MACComputer.php";
class AuthenticatedCookie {
  use MACComputer;

  protected $name;
  protected $key_hmac;
  protected $expiration;
  protected $value;

  // NOTE: every time you read an AuthenicatedCookie you update its expiration.
  public function __construct($name, $key_hmac, $expiration="30 days") {
    $this->name = $name;
    $this->key_hmac = $key_hmac;

    if(!is_string($key_hmac) || $key_hmac == "") {
      throw new UnexpectedValueException("HMAC key must be specified as a string (preferably a long random string!).");
    }

    $this->expiration = $expiration;

    $this->readCookie();
    $this->updateCookie();
  }

  public function setExpiration($expiration) {
    $this->expiration = $expiration;
    $this->updateCookie();
  }
  
  public function set($value) {
    $this->value = $value;
    $this->updateCookie();
  }

  public function get($value) {
    return $this->value;
  }

  public function clear() {
    $this->value = null;
  }

  protected function readCookie() {
    if(isset($_COOKIE[$name])) {
      $cookie = $_COOKIE[$name];

      if(strlen($cookie) <= 64)   // nothing to read here, its not a valid cookie.
        return false;

      $hash = substr($cookie, 0, 64);
      $message = substr($cookie, 64);

      $message = $this->readMessage($message, $hash);
      $this->value = $message;
    }
  }

  protected function updateCookie() {
    $prepared = $this->prepareMessage($this->value);

    // TODO: take in all the other parameters somewhere for this.
    setcookie($name, $prepared['hash'] . $prepared['message'], $this->computeExpiration(), "/");
  }

  public function __toString() {
    echo "AuthenticatedCookie: " . $this->value;
  }

  protected function computeExpiration() {
    return strtotime("+" . $this->expiration, time());
  }
}

if(!function_exists('hash_equals')) {
  function hash_equals($str1, $str2) {
    if(strlen($str1) != strlen($str2)) {
      return false;
    } else {
      $res = $str1 ^ $str2;
      $ret = 0;
      for($i = strlen($res) - 1; $i >= 0; $i--) $ret |= ord($res[$i]);
      return !$ret;
    }
  }
}
