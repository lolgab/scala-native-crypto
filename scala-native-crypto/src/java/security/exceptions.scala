package java.security

class NoSuchAlgorithmException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cuase: Throwable) = this(null, cuase)
}

class NoSuchProviderException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
}

class UnrecoverableKeyException(msg: String)
    extends GeneralSecurityException(msg) {
  def this() = this(null)
}

class KeyStoreException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class DigestException(message: String, cause: Throwable)
    extends GeneralSecurityException(message, cause) {
  def this(message: String) = this(message, null)
  def this(cause: Throwable) = this(null, cause)
  def this() = this(null, null)
}

class InvalidAlgorithmParameterException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null);
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class InvalidKeyException(msg: String, cause: Throwable)
    extends KeyException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class InvalidParameterException(msg: String, cause: Throwable)
    extends IllegalArgumentException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class KeyManagementException(message: String, cause: Throwable)
    extends KeyException(message, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class KeyException(message: String, cause: Throwable)
    extends GeneralSecurityException(message, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class ProviderException(msg: String, cause: Throwable)
    extends RuntimeException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class SignatureException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}
