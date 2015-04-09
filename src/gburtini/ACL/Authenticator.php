<?php
namespace gburtini\ACL;
class Authenticator {
  // this is a class that users will extend (replace authenticate) to create authenticators.
  public function authenticate($user, $password, $roles=null) {
    // returns either false or the internal ID for this user AND the roles appropriate.
    // if no roles are provided, the roles passed in are assumed good.
    throw new Exception("Authenticator needs to be implemented.");
  }
}

?>
