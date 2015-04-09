PHP-ACL: Simple Access Control Lists
====================================

_A simple, dependency-free (in use) user/login/cookie management, role and user-level access control system._

This is a very straightforward, simple and easy to use user system, ready to be extended for any purpose.

The ACL component is based on Nette\Security which was itself based on Zend_Acl.

Installation
------------
You can clone the repository and work with the files directly, but everything is set up for composer, which makes it simple:

    composer require gburtini/acl

Usage
-----
There are three parts to using this package.

* Implementing an Authenticator for your use-case
* Developing the access control lists.
* Integrating the User class.

Each can be complex or simple depending on your use case.

An Authenticator is a class that implements the method ``->authenticate($username, $password[, $roles])``, verifies the users name and password (and if specified, requested roles), and returns a unique identifier for the user and a set of roles that belong to him in the format ['id' => 123, 'roles' => ['administrator']]. A SimpleAuthenticator is provided in SimpleAuthenticator.php for demonstration purposes
````
                <?php
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
````

This is not a good authenticator, as it gives users any roles they request (note that requesting roles is optional, you can ignore that parameter and simply return the list of valid roles for this user) and stores usernames and passwords in totality and in plain text. A better Authenticator will interact with your users table or other datastore.

Developing the access control list, requires using the class ACL. An example follows.
````
                  $acl = new ACL();
                  $acl->addRole("administrator");
                  $acl->addRole("manager");
                  $acl->addRole("client");
                  $acl->addRole("guest");
                  // or, $acl->addRole("administrator", ["manager"]);, indicating that administrator inherits manager's permissions.

                  $acl->addResource("files");
                  $acl->addResource("client_lists");

                  $acl->deny("guest", ["files", "client_lists"]);
                  $acl->allow(['administrator', 'manager'], ['files', 'client_lists'], ['read', 'write'], function($acl, $testing_role, $testing_resource, $testing_privilege) {
                    // this function is an assertion that returns true/false if the rule should apply.
                    $arguments = $acl->getQueriedOtherArguments();
                    if($arguments['user_id'] == 4)  // we can pass in user ID and indeed file/list ID via the other arguments system.
                      return false;
                  }));

````
Note that you can call ``serialize()`` on the ``$acl`` object and will get a version you can store in your database. For more information in how inheritance and role/resources work, the Nette\Security and Zend_Acl documentation applies almost directly to this code.

Finally, to integrate a User class to tie it all together. We can use the built in User or we can extend it to provide some of our own functionality (in particular, storing information other than the identifier about the user). For this demonstration, we'll use the provided User class (in User.php)

````
                // provide HMAC and AES keys.
                $user = new User('SNgsHsd#T$DaN R*Ol~O6z+a+[v}@3)6%-X0nHH|%#ag+hYV 5f|zs}6;T|wM?3+', 'ALPHb92wzIamFw39VHLTiv6rY8i6EiEU8Plghvbhu547iPlgqlHSy76F');
                $user->setAuthenticator(new SimpleAuthenticator([
                  'johnny' => 'apples33d',
                  'thelma' => 'J!JHndmTivE'
                ]));
                $user->setExpiration("30 days");
                $user->setACL($acl);  // from our previous set up
                // if the user is not signed in, his only role is 'guest' and his ID is null.
                // but you can check with $user->isLoggedIn(), $user->whoAmI() or $user->roles()

                // if the user has a login stored in his cookies, he will be already authenticated. If he weren't, you can try to authenticate him with $user->login($username, $password); -- this will throw an exception if the login fails.

                if($user->can("files", "view", 1)) {
                    echo "I'm allowed to view file #1";
                }
````

You're done. That's the whole system.

Future Work
-----------
There is much that can be done, but nothing that I need immediately. Pull requests are invited.

* Change all exceptions to throw different classes so that reasons can be caught cleanly.
* Implement some other authenticators, user classes.
* Document how to extend the user class for your own implementation.
* Verify and extract the crypto required for User.php in to its own dependent package.
* Integrate with gburtini/Hooks to allow events to occur on user instances.
* Document every method in this file (README.md).

There is further work that I would prefer to keep *out* of this package for simplicity, but would be of value to many users of the package:

* User storage functionality (users, including their permissions, written to the database).
* Further user identity functionality (right now, the User class is intended to be extended to provide this).

License
-------
As parts of the code are derived from New BSD licensed code, we have followed in the spirit and this package itself is released under the New BSD.

Novel contributions. Copyright (c) 2015 Giuseppe Burtini.
Zend_Acl original code. Copyright (c) 2005-2015, Zend Technologies USA, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of Zend Technologies USA, Inc. or Giuseppe Burtini nor the names of any contributors may be used to endorse or promote products derived from this software without specific prior written permission.

_THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE._
