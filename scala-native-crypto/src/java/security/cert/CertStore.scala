package java.security.cert

import java.security.{
  InvalidAlgorithmParameterException,
  NoSuchAlgorithmException
}
import java.security.Provider
import java.util.Collection
import java.util.Objects.requireNonNull

abstract class CertStoreSpi {}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CertStore.html
 */
abstract class CertStore protected (
    spi: CertStoreSpi,
    provider: Provider,
    csType: String,
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

  import com.github.lolgab.scalanativecrypto.{OpenSSLProvider, JcaService}

  def getInstance(
      csType: String,
      params: CertStoreParameters
  ): CertStore =
    getInstance(csType, params, OpenSSLProvider.defaultInstance)

  def getInstance(
      csType: String,
      params: CertStoreParameters,
      provider: String
  ): CertStore =
    throw new UnsupportedOperationException()

  def getInstance(
      csType: String,
      params: CertStoreParameters,
      provider: Provider
  ): CertStore = {
    requireNonNull(csType, "type name must be not null")
    requireNonNull(provider, "provider must be not null")
    require(csType.nonEmpty, "empty type name")

    val service =
      provider.getService(JcaService.CertStore.name, csType)
    if (service == null)
      throw new NoSuchAlgorithmException(
        s"Algorithm ${csType} not found in provider ${provider.getName()}"
      )
    if (!service.supportsParameter(params))
      throw new InvalidAlgorithmParameterException(
        s"parameters ${params} do not match the algorithm ${csType}"
      )
    service.newInstance(params).asInstanceOf[CertStore]
  }

  def getDefaultType(): String =
    "Collection"

}
