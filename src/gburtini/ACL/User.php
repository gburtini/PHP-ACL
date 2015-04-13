<?php
namespace gburtini\ACL;
require_once dirname(__FILE__) . "/compatibility.php";
/**
 * This class provides the basic login and permissions functionality for our role-based
 * access system.
 */
class User {
  protected $id;
  protected $acl;
  protected $authenticator;
  protected $roles = ['guest'];

  protected $expiration = "30 days";

  const COOKIE_NAME = "usercookie";
  private $HMAC_SECRET_KEY;
  private $AES_SECRET_KEY;

  // The keys should be specified as secret/private site configuration and passed in here, the same for every request.
  public function __construct($hmackey, $aeskey) {
    $this->HMAC_SECRET_KEY = $hmackey;
    $this->HMAC_AES_KEY = $aeskey;
    $this->internalLogin();
  }

  public function isLoggedIn() {
    return $this->id !== null;
  }
  public function whoAmI() {
    return $this->id;
  }
  public function roles() { return $this->roles; }

  // NOTE: you can override these methods to use another method of storing logins.
  protected function internalLogin() {
      // check if a login exists.
      $message = $this->readMessage($_COOKIE[self::COOKIE_NAME], $_COOKIE[self::COOKIE_NAME."_hmac"]);
      if($message === false)
        return false;
      else {
        if(time() > $message['now'] && time() < $message['expires']) {
          $this->id = $message['id'];
          $this->roles = $message['roles'];
        }
        else {
          return false;
        }
      }
  }

  protected function setInternalLogin($id) {
    $this->id = $id;

    $expires = $this->computeExpiration();
    $message = ['id' => $id, 'roles' => $this->roles, 'now' => time(), 'expires' => $expires];
    list($message, $hash) = $this->prepareMessage($message);

    // NOTE: these cookies could be set longer to allow detecting why a login failed?
    setcookie(self::COOKIE_NAME, $message, $expires, "/");
    setcookie(self::COOKIE_NAME . "_hmac", $hash, $expires, "/");
  }


  /**
   * Passed in roles are solely optional here. It allows you to "request" roles
   * and have the authenticator determine whether it wishes to dole them out.
   *
   * NOTE: in the current implementation, roles are overwritten here IF you changed ID.
   * If you want to use this code in a way where you iteratively request more and more
   * permission roles that is acceptable as long as the authenticator returns the same ID
   */
  public function login($username, $password, $roles=null) {
    if(($response = $this->authenticator->authenticate($username, $password, $roles)) !== false) {
      // good, set login parameters.
      $this->setInternalLogin($response['id']);
      if($response['id'] != $this->id)
        $this->roles = $response['roles'];
      else
        $this->roles = array_unique(array_merge($this->roles, $response['roles']));
      return $response;
    } else {
      throw new Exceptions\InvalidLoginException("Invalid login.");
    }
  }

  public function logout() {
    setcookie(self::COOKIE_NAME, "", time()+1, "/");
    setcookie(self::COOKIE_NAME . "_hmac", "", time()+1, "/");

    $this->id = null;
    $this->roles = ["guest"];
  }

  /**
   * Set the cookie expiration time in relation to when login is called.
   */
  public function setExpiration($time = "30 days") {
    //$expiration = strtotime("+" . $time);
    $this->expiration = $time;
  }

  /**
   * Set the authenticator to be used. See SimpleAuthenticator.php for more information.
   */
  public function setAuthenticator($authenticator) {
    $this->authenticator = $authenticator;
  }

  /**
   * Set the ACL set to be used. An instance of the ACL class.
   */
  public function setACL($acl) {
    $this->acl = $acl;
  }

  /**
   * Returns true or false if you can access the resource, action, ID set.
   * Note for implementors that when you're setting up the ACL, you have the option to
   * specify an assertion function. The assertion function will receive $id and the calling
   * user's user_id to allow user-level permissions.
   */
  public function can($resource, $action, $id=null) {
    if($this->acl === null)
      throw new \RuntimeException("You haven't set an ACL.");

    // a user can do something if any of his roles can do it.
    foreach($this->roles as $role) {
      if($this->acl->isAllowed($role, $resource, $action, [
        'id' => $id,
        'user_id' => $this->id
        // NOTE: any other arguments to the ACL assertions here.
      ]) == true)
        return true;
    }
    return false;
  }

  protected function computeExpiration() {
    return strtotime("+" . $this->expiration, time());
  }

  /**
  * Internal crypto code - I really hate having all this (too) low level crypto here...
  * A reminder that this code has absolutely no warranty express or implied, not even the
  * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Don't roll
  * your own crypto.
  **/
  protected function readMessage($cipher, $hash) {
      $cipher = base64_decode($cipher);
      $hash = base64_decode($hash);
      if(empty($cipher) || empty($hash)) return false;
      if(!\hash_equals($this->hash($cipher), $hash))
        return false;

      $iv_size = $this->ivSize();
      $iv_dec = substr($cipher, 0, $iv_size);
      $ciphertext_dec = substr($cipher, $iv_size);
      $plaintext_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->AES_SECRET_KEY, $ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec);
      return json_decode($plaintext_dec);
  }

  /*
   * It has been brought to my attention that it is not a requirement to encrypt
   * the token ($message), because the HMAC will ensure it is not tampered with.
   * Removing the crypto here would greatly reduce the complexity of this part of
   * the code.
   */
  protected function prepareMessage($message) {
    $plaintext = json_encode($message);
    $iv_size = $this->ivSize();

    $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
    $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->AES_SECRET_KEY, $plaintext, MCRYPT_MODE_CBC, $iv);
    $ciphertext = $iv . $ciphertext;
    $ciphertext_base64 = base64_encode($ciphertext);

    $hash = $this->hash($ciphertext);
    $hash_base64 = base64_encode($hash);
    return [$ciphertext_base64, $hash_base64];
  }

  protected function hash($message) {
    $hash = hash_hmac('sha256', $message, $this->HMAC_SECRET_KEY);
    return $hash;
  }
  protected function ivSize() {
    return mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
  }
}
?>
