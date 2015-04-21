<?php
namespace gburtini\ACL;
require_once dirname(__FILE__) . "/compatibility.php";

/*
 * Important note: if ACL_USE_CRYPTO is falsy, this DISABLES AES encrypting the cooking, which means the ID and role messages are stored /in plain text/ on the client device.
 * HMAC validation still takes place which should prevent tampering. This is only recommended for development as the security in depth from encrypting the blobs is at least 
 * plausibly valuable.
 *
 * Disclaimer: I am not a cryptographer. I read OWASP regularly. I should not be advising cryptographic code at all. Please investigate this on your own prior to accepting the
 * implementation. This code comes with no warranty. You should read this in depth before implementing any authentication code: https://www.owasp.org/index.php/Authentication_Cheat_Sheet
 */
define("ACL_USE_CRYPTO", TRUE);

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
  // AES key is unnecessary if you have crypto off. For security reasons, it will throw an exception if crypto is on and it is unspecified. 
  public function __construct($hmackey, $aeskey=null) {
    if(ACL_USER_CRYPTO && ($aeskey === null)) // TODO: possibly check length of both keys here, ensure they are 'sufficient'.
        throw new Exception("Missing cryptographic key for AES.");

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
    // delete the cookies by setting them to blank (which won't auth.) and expiring them one second in the future.
    setcookie(self::COOKIE_NAME, "", time()+1, "/");
    setcookie(self::COOKIE_NAME . "_hmac", "", time()+1, "/");

    // clear the current settings... note that extending classes should be wary of a call to logout in this sense.
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
      $cipher = base64_decode($cipher, true);
      $hash = base64_decode($hash, true);
      if($cipher === false || $hash === false || empty($cipher) || empty($hash)) 
        return false;

      // always authenticate as a first step, exit if it doesn't pass: http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
      // this should be the step that any user modified messages get dumped. if anything bad happens after this, we must assume it is
      // a security risk.
      if(!\hash_equals($this->hash($cipher), $hash))
        return false;

      // important note: if ACL_USE_CRYPTO is set to false, this DISABLES CRYPTO, which means the ID and role messages are stored /in plain text/ on the client device.
      // they are verified by the HMAC for tampering, but this will allow users to read their own roles at a minimum. My recommendation is to only use crypto-free 
      // tokens for development, however, there is no cryptographic argument that requires these to be encrypted.
      if(!ACL_USE_CRYPTO) {
        $plaintext_dec = $cipher; // without crypto these are identical. the HMAC enforces the nonmodification.
        return json_decode($plaintext_dec);
      }

      $iv_size = $this->ivSize();
      if($iv_size === false)
         throw new RuntimeException("Cowardly refusing to decrypt when IV size is unknown (do not want to run cryptoprimitives on unknown input).");
 
      $iv_dec = substr($cipher, 0, $iv_size);
      if($iv_dec === false)
         throw new RuntimeException("Cowardly refusing to decrypt when IV cannot be found.");

      $ciphertext_dec = substr($cipher, $iv_size);
      $plaintext_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->AES_SECRET_KEY, $ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec);
      if($plaintext_dec === false)
         throw new RuntimeException("Cowardly refusing to continue decryption when Rijndael failed.");
      $plaintext_dec = rtrim($plaintext_dec, "\0\4");	// this is scary, but mcrypt_encrypt padded with zeros.

      return json_decode($plaintext_dec, true);
  }

  /*
   * It has been brought to my attention that it is not a requirement to encrypt
   * the token ($message), because the HMAC will ensure it is not tampered with.
   * Removing the crypto here would greatly reduce the complexity of this part of
   * the code.
   *
   * Implements encrypt-then-authenticate. http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
   */
  protected function prepareMessage($message) {
    $plaintext = json_encode($message);
    if(ACL_USE_CRYPTO) {
       $iv_size = $this->ivSize();
       if($iv_size === false)
          throw new RuntimeException("Cowardly refusing to return ciphertext when IV creation failed (size calculation is false?)."); 

       $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
       if($iv === false)
          throw new RuntimeException("Cowardly refusing to return ciphertext when IV creation failed."); 
     
       $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->AES_SECRET_KEY, $plaintext, MCRYPT_MODE_CBC, $iv);
       if($ciphertext === false)
          throw new RuntimeException("Cowardly refusing to return ciphertext when Rijndael call failed."); 

       $ciphertext = $iv . $ciphertext;
    } else {
      // note if ACL_USE_CRYPTO is disabled we just mock ciphertext to the plaintext.
      $ciphertext = $plaintext;
    }

    $ciphertext_base64 = base64_encode($ciphertext);

    $hash = $this->hash($ciphertext);
    if($hash === false)
       throw new RuntimeException("Cowardly refusing to return ciphertext when hash calculation fails. Check that the appropriate HMAC algorithm is available.");

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
