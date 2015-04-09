<?php
  namespace gburtini\ACL;
  class SimpleAuthenticator extends Authenticator {
    private $users;

    public function __construct($userpasses) {
      $this->users = $userpasses;
    }

    public function authenticate($user, $password, $roles=null) {
      if($this->users[$user] === $password)
        return ['id' => $user, 'roles' => $roles];  // in reality, you want to pick/confirm roles for this user.
      return false;
    }
  }
?>
