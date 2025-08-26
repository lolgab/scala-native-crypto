package java.security.cert

import java.security.GeneralSecurityException

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/CertificateException.html
class CertificateException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}
