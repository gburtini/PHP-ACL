<?php
namespace gburtini\ACL;
class Authenticator {
  // this is a class that users will extend (replace authenticate) to create authenticators.
  public function authenticate($user, $password, $roles=null) {
    // returns either false or the internal ID for this user AND the roles appropriate.
    // if no roles are provided, the roles passed in are assumed good.

    /* 
     * Some basic rules for security and sanitation when implementing an authenticator. You should consider them all 
     * (they're all important!), but also consider and understand the limitations for your application.
     *
     * 1. Authenticators should be CASE INSENSITIVE to $user - at a minimum, they should not allow smith and SmItH to 
     * both exist as users. 
     *
     * 2. User registration should enforce secure passwords. Passwords shorter than 10 characters should be considered 
     * weak in most applications. 
     *    - For online-only authentication with strong hashing for storing passwords, shorter passwords may be reasonable, 
     *    but you /must/ detect, log and attempt to prevent brute force attacks.
     *    - For less "important" authentications weaker password rules can be considered, but stronger requirements prevent 
     *    password reuse, which is desirable in all cases.
     *
     * 3. Authenticators should detect brute force attacks. I have a toolkit for assisting with this: https://github.com/gburtini/PHP-Brute-Force-Defense
     *
     * 4. User interfaces should encourage passphrases over passwords. This is an increasingly accepted recommendation. 
     * See: https://xkcd.com/936/ for a humorous (but well-advised) description.
     *
     * 5. PASSWORDS SHOULD NEVER BE STORED IN PLAINTEXT ON THE SERVER. Use php.net/password_hash or scrypt to store your 
     * passwords. Always.
     *    - This prevents "password recovery" in any mechanism other than changing the password with a token login. 
     *    This may be unfortunate for your user interface. 
     *    - See: https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet
     *
     * 6. When using $roles, you should require reauthentication for "sensitive features." Consider having a user role and a user-sudo 
     * role, which allows access to more advanced features.
     *    - This eliminates the risk of an abandoned session / captured session.
     *    - Examples of sensitive features might be accessing private information (location, money, API keys, etc.) or changing email 
     *    address or password.
     *
     * 7. In general, do not display error messages that indicate why the authentication failed. ("Invalid username or password." 
     * is an appropriate response).
     *    - This may hurt usability, and in general, usernames should not be considered "secret information." 
     *    - Leaking username's existence on the login form is only an issue if your registration form doesn't do it (which it 
     *    probably does!). 
     *    - If you want to keep the existence of usernames secret, ensure there is at least a CAPTCHA on the registration form.
     *    - Brute force limitations on both these forms can aid in preventing the enumeration of valid user accounts.
     *
     * 8. There is much more to consider! This is not everything. Be cautious. Consider what information is leaking and what attack vectors you are considering.
     */

    throw new \BadMethodCallException("Authenticator needs to be implemented.");
  }
}

?>
