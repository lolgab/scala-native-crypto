package com.github.lolgab.scalanativecrypto.crypto.cert

import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.{PublicKey, Provider, Principal}
import java.lang.ref.Cleaner
import java.util.{Date, Collection}
import java.util.{Set => JSet, List => JList}
import javax.security.auth.x500.X500Principal

import scala.scalanative.unsafe.{fromCString, stackalloc}

import _root_.com.github.lolgab.scalanativecrypto.internal.crypto
import _root_.com.github.lolgab.scalanativecrypto.internal.crypto.X509_*
import _root_.com.github.lolgab.scalanativecrypto.internal.Constants.XN_FLAG_RFC2253
import scala.scalanative.unsafe.CChar

class OpenSSLX509Certificate protected[scalanativecrypto] (val ptr: X509_*)
    extends X509Certificate() {

  Cleaner
    .create()
    .register(
      this,
      new Runnable { override def run(): Unit = crypto.X509_free(ptr) }
    )

  def getIssuerDN(): Principal = throw new UnsupportedOperationException(
    "getIssuerDN is deprecated since Java 16, use getIssuerX500Principal() instead"
  )

  def getSubjectDN(): Principal = throw new UnsupportedOperationException(
    "getSubjectDN is deprecated since Java 16, use getSubjectX500Principal() instead"
  )

  override def getNotAfter(): Date = {
    crypto.X509_get0_notAfter(ptr)
    ???
  }

  override def getNotBefore(): Date = {
    crypto.X509_get0_notBefore(ptr)
    ???
  }

  override def getSerialNumber(): BigInteger = {
    crypto.X509_get0_serialNumber(ptr)
    // ASN1_INTEGER_to_BN
    // BN_bn2dec
    ???
  }

  override def getSigAlgName(): String = ???

  override def getSigAlgOID(): String = ???

  override def getSigAlgParams(): Array[Byte] = ???

  override def getSignature(): Array[Byte] = ???

  override def getTBSCertificate(): Array[Byte] = ???

  override def getVersion(): Int = {
    // X509_get_version(ptr) + 1
    ???
  }

  override def getEncoded(): Array[Byte] = ???

  override def verify(key: PublicKey): Unit = ???

  override def verify(key: PublicKey, sigProvider: Provider): Unit = ???

  override def verify(key: PublicKey, sigProvider: String): Unit = ???

  override def getPublicKey(): PublicKey = {
    crypto.X509_get0_pubkey(ptr)
    ???
  }

  override def hasUnsupportedCriticalExtension(): Boolean = ???

  override def getCriticalExtensionOIDs(): JSet[String] = ???

  override def getNonCriticalExtensionOIDs(): JSet[String] = ???

  override def getExtensionValue(oid: String): Array[Byte] = ???

  override def checkValidity(): Unit = ???

  override def checkValidity(date: Date): Unit = ???

  override def getBasicConstraints(): Int = ???

  override def getExtendedKeyUsage(): JList[String] = ???

  override def getIssuerAlternativeNames(): Collection[JList[_]] = ???

  override def getIssuerUniqueID(): Array[Boolean] = ???

  override def getIssuerX500Principal(): X500Principal = ???

  override def getKeyUsage(): Array[Boolean] = ???

  override def getSubjectAlternativeNames(): Collection[JList[_]] = ???

  override def getSubjectUniqueID(): Array[Boolean] = ???

  override def getSubjectX500Principal(): X500Principal = {
    val bio = crypto.BIO_new(crypto.BIO_s_mem())

    try {
      val sn = crypto.X509_get_subject_name(ptr)

      val ret = crypto.X509_NAME_print_ex(bio, sn, 0, XN_FLAG_RFC2253)
      if (ret == -1)
        throw new RuntimeException("Failed to get X509_NAME")

      // RFC 5280 limits the Subject Name to 64 Characters in UTF-8
      // 4 bytes * 64 = 256 bytes should be enough to hold the data
      val buf = stackalloc[CChar](256)
      val getsRet = crypto.BIO_gets(bio, buf, 256)
      if (getsRet == -1)
        throw new RuntimeException("Failed to get memory buffer from BIO")
      val name = fromCString(buf)

      new X500Principal(name)
    } finally {
      crypto.BIO_free(bio)
    }
  }

  override def toString: String = ???

}
