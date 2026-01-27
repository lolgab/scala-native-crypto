package java.security.cert

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/CRL.html
abstract class CRL protected (crlType: String) {
  final def getType(): String = crlType

  def isRevoked(cert: Certificate): Boolean

}
