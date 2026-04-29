package com.github.lolgab.scalanativecrypto.crypto

import java.security.Provider
import java.security.cert.{
  CertificateFactory,
  CertificateFactorySpi,
  CertPath,
  Certificate,
  CRL
}
import java.security.cert.CertificateException
import java.io.InputStream
import java.io.IOException
import java.util.{Collection, Iterator, List => JList}
import java.util.Objects.requireNonNull

import scala.scalanative.unsafe.{Zone, Ptr, alloc}

import _root_.com.github.lolgab.scalanativecrypto.internal.crypto
import _root_.com.github.lolgab.scalanativecrypto.crypto.cert.OpenSSLX509Certificate

class OpenSSLX509CertificateFactorySpi extends CertificateFactorySpi {

  def engineGenerateCertificate(is: InputStream): Certificate = {
    requireNonNull(is, "input stream must not be null")

    try {
      if (is.markSupported()) is.mark(is.available() + 1)

      val bytes = is.readAllBytes()
      if (bytes.length == 0)
        throw new IllegalArgumentException(
          "input stream does not contain a valid certificate"
        )

      val x509: OpenSSLX509Certificate = Zone.acquire { implicit zone =>
        val buf = alloc[Byte](bytes.length)
        for (i <- bytes.indices) {
          buf(i) = bytes(i)
        }
        val bp = crypto.BIO_new_mem_buf(buf, bytes.length)

        val ptr = crypto.PEM_read_bio_X509(bp, null, null, null)
        if (ptr == null) {
          throw new CertificateException(
            "Failed to parse input certificate"
          )
        }

        new OpenSSLX509Certificate(ptr)
      }

      x509
    } catch {
      case exc: Exception => {
        try
          if (is.markSupported()) is.reset()
        catch {
          case e: IOException =>
            throw new IOException(
              "Failed to reset input stream after inability to read certificate",
              e
            )
        }

        throw exc
      }
    }
  }

  override def engineGetCertPathEncodings(): Iterator[String] =
    ???

  override def engineGenerateCertPath(is: InputStream): CertPath =
    ???

  override def engineGenerateCertPath(
      is: InputStream,
      encoding: String
  ): CertPath =
    ???

  override def engineGenerateCertPath(
      certificates: JList[_ <: Certificate]
  ): CertPath =
    ???

  def engineGenerateCertificates(
      is: InputStream
  ): Collection[? <: Certificate] = {
    requireNonNull(is, "input stream must not be null")

    ???
  }

  def engineGenerateCRL(is: InputStream): CRL =
    ???

  def engineGenerateCRLs(is: InputStream): Collection[? <: CRL] =
    ???
}

final class OpenSSLX509CertificateFactory protected[scalanativecrypto] (
    provider: Provider,
    algorithm: String
) extends CertificateFactory(
      new OpenSSLX509CertificateFactorySpi(),
      provider,
      algorithm
    )
