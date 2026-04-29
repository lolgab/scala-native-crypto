package java.security.cert

import java.io.InputStream
import java.security.Provider
import java.util.{Collection, Iterator, List => JList}
import java.util.Objects.requireNonNull
import java.security.NoSuchAlgorithmException

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CertificateFactorySpi
abstract class CertificateFactorySpi {

  def engineGenerateCertificate(is: InputStream): Certificate

  def engineGetCertPathEncodings(): Iterator[String]

  def engineGenerateCertPath(is: InputStream): CertPath

  def engineGenerateCertPath(is: InputStream, encoding: String): CertPath

  def engineGenerateCertPath(certificates: JList[? <: Certificate]): CertPath

  def engineGenerateCertificates(is: InputStream): Collection[? <: Certificate]

  def engineGenerateCRL(is: InputStream): CRL

  def engineGenerateCRLs(is: InputStream): Collection[? <: CRL]

}

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CertificateFactory
abstract class CertificateFactory protected (
    spi: CertificateFactorySpi,
    provider: Provider,
    certType: String
) {

  final def getProvider(): Provider =
    provider

  final def getType(): String =
    certType

  final def generateCertificate(is: InputStream): Certificate =
    spi.engineGenerateCertificate(is)

  final def getCertPathEncodings(): Iterator[String] =
    spi.engineGetCertPathEncodings()

  final def generateCertPath(is: InputStream): CertPath =
    spi.engineGenerateCertPath(is)

  final def generateCertPath(is: InputStream, encoding: String): CertPath =
    spi.engineGenerateCertPath(is, encoding)

  final def generateCertPath(certificates: JList[? <: Certificate]): CertPath =
    spi.engineGenerateCertPath(certificates)

  final def generateCertificates(
      is: InputStream
  ): Collection[? <: Certificate] =
    spi.engineGenerateCertificates(is)

  final def generateCRL(is: InputStream): CRL =
    spi.engineGenerateCRL(is)

  final def generateCRLs(is: InputStream): Collection[? <: CRL] =
    spi.engineGenerateCRLs(is)

}

object CertificateFactory {

  import com.github.lolgab.scalanativecrypto.{OpenSSLProvider, JcaService}

  def getInstance(certType: String): CertificateFactory =
    getInstance(certType, OpenSSLProvider.defaultInstance)

  def getInstance(certType: String, provider: String): CertificateFactory =
    throw new UnsupportedOperationException()

  def getInstance(certType: String, provider: Provider): CertificateFactory = {
    requireNonNull(certType, "type name must be not null")
    requireNonNull(provider, "provider must be not null")
    require(certType.nonEmpty, "empty type name")

    val service =
      provider.getService(JcaService.CertificateFactory.name, certType)
    if (service == null)
      throw new NoSuchAlgorithmException(
        s"Algorithm ${certType} not found in provider ${provider.getName()}"
      )
    service.newInstance(null).asInstanceOf[CertificateFactory]
  }

}
