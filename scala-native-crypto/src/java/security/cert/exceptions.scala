package java.security.cert

import java.security.GeneralSecurityException
import java.util.{Date, Map => JMap}
import javax.security.auth.x500.X500Principal

class CertificateEncodingException(msg: String, cause: Throwable)
    extends CertificateException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class CertificateException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

class CertificateExpiredException(msg: String)
    extends CertificateException(msg, null) {
  def this() = this(null)
}

class CertificateNotYetValidException(msg: String)
    extends CertificateException(msg, null) {
  def this() = this(null)
}

class CertificateParsingException(msg: String, cause: Throwable)
    extends CertificateException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

/**
 * Ref:
 * <https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CertificateRevokedException.html>
 */
class CertificateRevokedException(
    revocationDate: Date,
    reason: CRLReason,
    authority: X500Principal,
    extensions: JMap[String, Extension]
) extends CertificateException(null, null) {
  if (
    revocationDate == null || reason == null
    || authority == null || extensions == null
  ) {
    throw new NullPointerException(
      "revocationDate, reason, authority and extensions must not be null"
    )
  }

  // TODO:
  // Throw `ClassCastException` if extensions contains an incorrectly typed key or value

  def getRevocationDate(): Date = revocationDate
  def getRevocationReason(): CRLReason = reason
  def getAuthorityName(): X500Principal = authority
  def getExtensions(): JMap[String, Extension] = extensions

  // Invalidity Date extension OID ("2.5.29.24").
  def getInvalidityDate(): Date = {
    val ext = extensions.get("2.5.29.24")

    if (ext == null) {
      null
    } else {
      throw new NotImplementedError(
        "Parsing of the Invalidity Date extension is not implemented"
      )
    }
  }
}

class CertPathBuilderException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null);
  def this(cause: Throwable) = this(null, cause)
}

class CertPathValidatorException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null);
  def this(cause: Throwable) = this(null, cause)
}

class CertStoreException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null);
  def this(cause: Throwable) = this(null, cause)
}

class CRLException(msg: String, cause: Throwable)
    extends GeneralSecurityException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null);
  def this(cause: Throwable) = this(null, cause)
}
