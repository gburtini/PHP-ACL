<?php
namespace gburtini\AuthenticatedStorage;

/*
* Disclaimer: I am not a cryptographer. I read OWASP regularly. I should not be advising cryptographic code at all. Please investigate this on your own prior to accepting the
* implementation. This code comes with no warranty. You should read this in depth before implementing any authentication code: https://www.owasp.org/index.php/Authentication_Cheat_Sheet
*/
class AESAuthenticatedCookie extends AuthenticatedCookie {
  protected $key_aes;
  public function __construct($name, $key_hmac, $key_aes, $expiration="30 days") {
    $this->key_aes = $key_aes;
    parent::__construct($name, $key_hmac, $expiration);
  }

  /**
  * A reminder that this code has absolutely no warranty express or implied, not even the
  * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Don't roll
  * your own crypto.
  **/
  protected function preparePlaintext($plaintext) {
    $iv_size = static::ivSize();
    if($iv_size === false)
       throw new RuntimeException("Cowardly refusing to return ciphertext when IV creation failed (size calculation is false?).");

    $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
    if($iv === false)
       throw new RuntimeException("Cowardly refusing to return ciphertext when IV creation failed.");

    $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key_aes, $plaintext, MCRYPT_MODE_CBC, $iv);
    if($ciphertext === false)
       throw new RuntimeException("Cowardly refusing to return ciphertext when Rijndael call failed.");

    $ciphertext = $iv . $ciphertext;
    $ciphertext_base64 = base64_encode($ciphertext);
    return $ciphertext_base64;
  }

  protected function prepareCiphertext($ciphertext) {
    $iv_size = static::ivSize();
    if($iv_size === false)
       throw new RuntimeException("Cowardly refusing to decrypt when IV size is unknown (do not want to run cryptoprimitives on unknown input).");

    $iv_dec = substr($ciphertext, 0, $iv_size);
    if($iv_dec === false)
       throw new RuntimeException("Cowardly refusing to decrypt when IV cannot be found.");

    $ciphertext_dec = substr($cipher, $iv_size);
    $plaintext_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->AES_SECRET_KEY, $ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec);
    if($plaintext_dec === false)
       throw new RuntimeException("Cowardly refusing to continue decryption when Rijndael failed.");
    $plaintext_dec = rtrim($plaintext_dec, "\0\4");	// this is scary, but mcrypt_encrypt padded with zeros.
    return $plaintext_dec;
  }

  protected static function ivSize() {
    return mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
  }
}
?>
