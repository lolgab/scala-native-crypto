package java.security.cert

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CertSelector.html
 */
trait CertSelector extends Cloneable {
  def `match`(cert: Certificate): Boolean
}
