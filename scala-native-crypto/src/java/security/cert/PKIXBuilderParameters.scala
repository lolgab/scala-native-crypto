package java.security.cert

import java.security.{InvalidParameterException, KeyStore}
import java.util.{Set => JSet}

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/PKIXBuilderParameters
class PKIXBuilderParameters private (
    trustAnchors: JSet[TrustAnchor],
    keyStore: KeyStore,
    targetConstraints: CertSelector
) extends PKIXParameters(trustAnchors, keyStore) {

  def this(trustAnchors: JSet[TrustAnchor], targetConstraints: CertSelector) =
    this(trustAnchors, null, targetConstraints)

  def this(keyStore: KeyStore, targetConstraints: CertSelector) =
    this(null, keyStore, targetConstraints)

  // JDK docs:
  // "The default maximum path length, if not specified, is 5."
  @volatile private var _maxPathLength: Int = 5

  def setMaxPathLength(maxPathLength: Int): Unit = {
    if (maxPathLength < -1) throw new InvalidParameterException()
    _maxPathLength = maxPathLength
  }

  def getMaxPathLength(): Int =
    _maxPathLength

  override def toString(): String = ???
}
