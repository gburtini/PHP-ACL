<?php
namespace gburtini\ACL;
use gburtini\AuthenticatedStorage\AESAuthenticatedCookie;
use gburtini\AuthenticatedStorage\AuthenticatedCookie;

/*
 * Important note: if ACL_USE_CRYPTO is falsy, this DISABLES AES encrypting the cooking, which means the ID and role messages are stored /in plain text/ on the client device.
 * HMAC validation still takes place which should prevent tampering. This is only recommended for development as the security in depth from encrypting the blobs is at least
 * plausibly valuable.
 *
 * Please see the notes in AuthenticatedStorage\AESAuthenticatedCookie before trusting this for cryptographic integrity.
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
  protected $cookie;

  // The keys should be specified as secret/private site configuration and passed in here, the same for every request.
  // AES key is unnecessary if you have crypto off. For security reasons, it will throw an exception if crypto is on and it is unspecified.
  public function __construct($hmackey, $aeskey=null) {
    if(ACL_USE_CRYPTO && ($aeskey === null)) // TODO: possibly check length of both keys here, ensure they are 'sufficient'.
        throw new Exception("Missing cryptographic key for AES.");

    if(!ACL_USE_CRYPTO) {
      $this->cookie = new AuthenticatedCookie(self::COOKIE_NAME, $hmackey, $this->expiration);
    } else {
      $this->cookie = new AESAuthenticatedCookie(self::COOKIE_NAME, $hmackey, $aeskey, $this->expiration);
    }

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
      $message = $this->cookie->get();
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

  protected function setInternalLogin() {
    $expires = $this->computeExpiration();
    $message = ['id' => $this->id, 'roles' => $this->roles, 'now' => time(), 'expires' => $expires];
    $this->cookie->set($message);
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
      if($response['id'] != $this->id)
        $this->roles = $response['roles'];
      else
        $this->roles = array_unique(array_merge($this->roles, $response['roles']));

      // NOTE: I am not super comfortable with this. Consider attack vectors that involve changing users mid-authentication.
      $this->id = $response['id'];
      $this->setInternalLogin();

      return $response;
    } else {
      throw new Exceptions\InvalidLoginException("Invalid login.");
    }
  }

  public function logout() {
    // delete the cookies by setting them to blank (which won't auth.) and expiring them one second in the future.
    $this->cookie->clear();

    // clear the current settings... note that extending classes should be wary of a call to logout in this sense.
    $this->id = null;
    $this->roles = ["guest"];
  }

  /**
   * Set the cookie expiration time in relation to when login is called.
   */
  public function setExpiration($time = "30 days") {
    $this->cookie->setExpiration($time);
    $this->expiration = $time;
  }

  // computes the cookie expiration time, it needs to be here because it is validated both by expiring the cookie client side
  // and by writing a tamper proof timestamp to the cookie.
  protected function computeExpiration() {
    return strtotime("+" . $this->expiration, time());
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
}
?>
