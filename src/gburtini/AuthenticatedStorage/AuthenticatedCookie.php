<?php
namespace gburtini\AuthenticatedStorage;

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

  public function get() {
    return $this->value;
  }

  public function clear() {
    $this->value = null;
  }

  protected function readCookie() {
    if(isset($_COOKIE[$this->name])) {
      $cookie = $_COOKIE[$this->name];

      // 88 = ceil(64 (simple hash length) / 3) * 4 for the base64 encoded hash size.
      if(strlen($cookie) <= 88)   // nothing to read here, its not a valid cookie.
        return false;

      $hash = substr($cookie, 0, 88);
      $message = substr($cookie, 88);

      $message = $this->readMessage($message, $hash);
      $this->value = $message;
    } else { $this->value = null; }
  }

  protected function updateCookie() {
    $prepared = $this->prepareMessage($this->value);

    // TODO: take in all the other parameters somewhere for this.
    setcookie($this->name, $prepared['hash'] . $prepared['message'], $this->computeExpiration(), "/");
  }

  public function __toString() {
    echo "AuthenticatedCookie: " . $this->value;
  }

  protected function computeExpiration() {
    return strtotime("+" . $this->expiration, time());
  }
}
