package java.security.cert

import java.security.Provider
import java.security.{
  InvalidAlgorithmParameterException,
  NoSuchAlgorithmException,
  NoSuchProviderException
}
import java.util.Collection

abstract class CertStoreSpi {}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CertStore.html
 */
abstract class CertStore protected (
    spi: CertStoreSpi,
    provider: Provider,
    `type`: String,
    params: CertStoreParameters
) {

  def getCertificates(selector: CertSelector): Collection[_ <: Certificate] =
    ???

  def getCRLs(selector: CRLSelector): Collection[_ <: CRL] =
    ???

  def getCertStoreParameters(): CertStoreParameters =
    ???

  def getType(): String =
    ???

  def getProvider(): Provider =
    ???

}

object CertStore {

  def getInstance(
      `type`: String,
      params: CertStoreParameters
  ): CertStore = ???

  def getInstance(
      `type`: String,
      params: CertStoreParameters,
      provider: String
  ): CertStore = ???

  def getInstance(
      `type`: String,
      params: CertStoreParameters,
      provider: Provider
  ): CertStore = ???

  def getDefaultType(): String = ???

}
