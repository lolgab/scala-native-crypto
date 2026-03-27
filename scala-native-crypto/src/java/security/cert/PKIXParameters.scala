package java.security.cert

import java.security.{
  InvalidAlgorithmParameterException,
  KeyStore,
  KeyStoreException
}
import java.util.{Date, List => JList, Set => JSet}
import java.util.Objects.requireNonNull

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/PKIXParameters.html
 */
class PKIXParameters protected[cert] (
    trustAnchors: JSet[TrustAnchor],
    keyStore: KeyStore
) extends CertPathParameters {

  def this(trustAnchors: JSet[TrustAnchor]) = this(
    {
      requireNonNull(trustAnchors, "the set of trust anchors must be non-null")
      if (trustAnchors.isEmpty())
        throw new InvalidAlgorithmParameterException(
          "the set of trust anchors must not be empty"
        )
      trustAnchors.forEach(ta => {
        if (!ta.isInstanceOf[TrustAnchor])
          throw new ClassCastException(
            "the elements in the Set must be type java.security.cert.TrustAnchor"
          )
      })

      trustAnchors
    },
    null
  )

  def this(keyStore: KeyStore) = this(
    null, {
      requireNonNull(keyStore, "the KeyStore must be non-null")
      // TODO:
      // `KeyStoreException` - if the keystore has not been initialized
      // `InvalidAlgorithmParameterException` - if the keystore does not contain at least one trusted certificate entry
      keyStore
    }
  )

  def getTrustAnchors(): JSet[TrustAnchor] = ???

  def setTrustAnchors(trustAnchors: JSet[TrustAnchor]): Unit = ???

  def getInitialPolicies(): JSet[String] = ???

  def setInitialPolicies(initialPolicies: JSet[String]): Unit = ???

  def setCertStores(stores: JList[CertStore]): Unit = ???

  def addCertStore(store: CertStore): Unit = ???

  def getCertStores(): JList[CertStore] = ???

  def setRevocationEnabled(value: Boolean): Unit = ???

  def isRevocationEnabled(): Boolean = ???

  def setExplicitPolicyRequired(value: Boolean): Unit = ???

  def isExplicitPolicyRequired(): Boolean = ???

  def setPolicyMappingInhibited(value: Boolean): Unit = ???

  def isPolicyMappingInhibited(): Boolean = ???

  def setAnyPolicyInhibited(value: Boolean): Unit = ???

  def isAnyPolicyInhibited(): Boolean = ???

  def setPolicyQualifiersRejected(qualifiersRejected: Boolean): Unit = ???

  def getPolicyQualifiersRejected(): Boolean = ???

  def getDate(): Date = ???

  def setDate(date: Date): Unit = ???

  def setCertPathCheckers(checkers: JList[PKIXCertPathChecker]): Unit = ???

  def getCertPathCheckers(): JList[PKIXCertPathChecker] = ???

  def addCertPathChecker(checker: PKIXCertPathChecker): Unit = ???

  def getSigProvider(): String = ???

  def setSigProvider(sigProvider: String): Unit = ???

  def getTargetCertConstraints(): CertSelector = ???

  def setTargetCertConstraints(selector: CertSelector): Unit = ???

  override def clone(): Object = ???

  override def toString(): String = ???

}
