<?php
namespace gburtini\AuthenticatedStorage;
/*
 * Provides tools to mixin MAC message storage functionality... note that if you want it
 * /encrypted/ in addition to validated you should override prepareCiphertext/Plaintext
 * this is a bit sloppy, but it is implemented this way so that we can provide JSON
 * wrapped functionality (so we can take in "any" primitive datatype).
 *
 * Even if you don't want it, prepareCiphertext (the prior-to-decoding prepare function)
 * and preparePlaintext (the prior-to-encoding prepare function) can be extended as you wish.
 */
trait MACComputer {
  protected function prepareCiphertext($ciphertext) {
    return $ciphertext;
  }

  protected function preparePlaintext($plaintext) {
    return $plaintext;
  }

  /*
   * Implements encrypt-then-authenticate as described by Moxie Marlinspike.
   * Reads a message and returns the message as it was saved from prepareMessage.
   */
  protected function readMessage($message, $hash) {
      // NOTE: empty has some strange behavior if you store "0". It should probably be discarded here.
      // Perhaps not that important since we JSON encode.
      if($message === false || $hash === false || empty($message) || empty($hash))
        return false;

      // always authenticate as a first step, exit if it doesn't pass: http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
      // this should be the step that any user modified messages get dumped. if anything bad happens after this, we must assume it is
      // a security risk.
      if(static::validateHash($message, $hash, $this->key_hmac) === false) {
        return false;
      }

      $message = $this->prepareCiphertext($message);

      return json_decode($message, true);
  }

  /*
   * Implements encrypt-then-authenticate if there were encryption specified.
   * See: http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
   *
   * Takes in a message and returns a dictionary of 'message' and 'hash' strings
   * where 'message' is the (possibly encrypted) plaintext and 'hash' is the validation
   * string to be passed in to readMessage.
   */
  protected function prepareMessage($message) {
    $plaintext = json_encode($message);

    $ciphertext = $this->preparePlaintext($plaintext);

    $hash = $this->hash($ciphertext);
    if($hash === false)
       throw new RuntimeException("Cowardly refusing to return ciphertext when hash calculation fails. Check that the appropriate HMAC algorithm is available.");

    return ['message' => $ciphertext, 'hash' => $hash];
  }

  /*
   * Validates a hash in a timing attack aware manner.
   */
  protected static function validateHash($message, $hash, $key) {
    if(!\hash_equals(static::hash($message, $key), $hash))
      return false;
    return true;
  }

  /*
   * Computes a hash as a base64 encoded sha256.
   */
  protected static function hash($message, $secret) {
    $hash = hash_hmac('sha256', $message, $secret);

    $hash = base64_encode($hash); // we do not decode the hash ever at this point, only compare as base64 encoded hashes.
    if($hash === false) // but base64_encode has a note in the documentation that it may return false.
      throw new RuntimeException("Failed to compute hash because base64 failed.");

    return $hash;
  }
}
?>
