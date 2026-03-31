package com.github.lolgab.scalanativecrypto.crypto

import java.security.{Provider, KeyStore, KeyStoreSpi}
import java.io.{InputStream, OutputStream}
import java.security.Key
import java.security.cert.Certificate
import java.util.{Date, Enumeration, Set => JSet}

final class OpenSSLKeyStore(provider: Provider, ksType: String)
    extends KeyStore(new OpenSSLKeyStoreSpi(), provider, ksType)

final class OpenSSLKeyStoreSpi protected[scalanativecrypto]
    extends KeyStoreSpi {

  override def engineGetKey(alias: String, password: Array[Char]): Key =
    ???

  override def engineGetCertificateChain(alias: String): Array[Certificate] =
    ???

  override def engineGetCertificate(alias: String): Certificate =
    ???

  override def engineGetCreationDate(alias: String): Date =
    ???

  override def engineSetKeyEntry(
      alias: String,
      key: Key,
      password: Array[Char],
      chain: Array[Certificate]
  ): Unit =
    ???

  override def engineSetKeyEntry(
      alias: String,
      key: Array[Byte],
      chain: Array[Certificate]
  ): Unit =
    ???

  override def engineSetCertificateEntry(
      alias: String,
      cert: Certificate
  ): Unit =
    ???

  override def engineDeleteEntry(alias: String): Unit =
    ???

  override def engineAliases(): Enumeration[String] =
    ???

  override def engineContainsAlias(alias: String): Boolean =
    ???

  override def engineSize(): Int =
    ???

  override def engineIsKeyEntry(alias: String): Boolean =
    ???

  override def engineIsCertificateEntry(alias: String): Boolean =
    ???

  override def engineGetCertificateAlias(cert: Certificate): String =
    ???

  override def engineStore(stream: OutputStream, password: Array[Char]): Unit =
    ???

  override def engineStore(param: KeyStore.LoadStoreParameter): Unit =
    ???

  override def engineLoad(stream: InputStream, password: Array[Char]): Unit =
    ???

  override def engineLoad(param: KeyStore.LoadStoreParameter): Unit =
    ???

  // @since JDK 18
  override def engineGetAttributes(
      alias: String
  ): JSet[KeyStore.Entry.Attribute] =
    ???

  override def engineGetEntry(
      alias: String,
      protParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry =
    ???

  override def engineSetEntry(
      alias: String,
      entry: KeyStore.Entry,
      protParam: KeyStore.ProtectionParameter
  ): Unit =
    ???

  override def engineEntryInstanceOf(
      alias: String,
      entryClass: Class[_ <: KeyStore.Entry]
  ): Boolean =
    ???

  // @since JDK 9
  override def engineProbe(stream: InputStream): Boolean =
    ???

}
