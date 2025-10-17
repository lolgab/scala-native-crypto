package java.security.cert

import java.io.InputStream
import java.security.Provider
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.util.{Collection, Iterator}
import java.util.{List => JList}
import java.util.Objects.requireNonNull

/// ## Refs
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CertificateFactory.html
abstract class CertificateFactory protected (
    // private val certFactorySpi: CertificateFactorySpi,
    private val provider: Provider,
    private val certType: String
) {
  final def getProvider(): Provider = provider

  final def getType(): String = certType

  def generateCertificate(is: InputStream): Certificate

  def getCertPathEncodings(): Iterator[String]

  def generateCertPath(is: InputStream): CertPath

  def generateCertPath(is: InputStream, encoding: String): CertPath

  def generateCertPath(
      certificates: JList[? <: Certificate]
  ): CertPath

  def generateCertificates(
      is: InputStream
  ): Collection[? <: Certificate]

  def generateCRL(is: InputStream): CRL

  def generateCRLs(is: InputStream): Collection[? <: CRL]

}

object CertificateFactory {
  def getInstance(certType: String): CertificateFactory = {
    requireNonNull(certType, "null type name")
    try {
      ???
    } catch {
      case e: NoSuchAlgorithmException =>
        throw new CertificateException(certType + " not found", e)
    }
  }

  def getInstance(
      certType: String,
      provider: String
  ): CertificateFactory = {
    requireNonNull(certType, "null type name")
    try {
      ???
    } catch {
      case e: NoSuchAlgorithmException =>
        throw new CertificateException(certType + " not found", e)
    }
  }

  def getInstance(
      certType: String,
      provider: Provider
  ): CertificateFactory = {
    requireNonNull(certType, "null type name")
    try {
      ???
    } catch {
      case e: NoSuchAlgorithmException =>
        throw new CertificateException(certType + " not found", e)
    }
  }
}
