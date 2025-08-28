package java.security

import java.io.{InputStream, OutputStream, IOException}
import java.util.{Collections, Date, Enumeration}
import java.util.{Set => JSet}
import java.util.Objects.requireNonNull
import java.security.cert.{Certificate, CertificateException}
import java.security.Key

import javax.crypto.SecretKey
import javax.security.auth.callback.{
  CallbackHandler,
  PasswordCallback,
  Callback,
  UnsupportedCallbackException
}

abstract class KeyStoreSpi {

  def engineGetKey(alias: String, password: Array[Char]): Key

  def engineGetCertificateChain(alias: String): Array[Certificate]

  def engineGetCertificate(alias: String): Certificate

  def engineGetCreationDate(alias: String): Date

  def engineSetKeyEntry(
      alias: String,
      key: Key,
      password: Array[Char],
      chain: Array[Certificate]
  ): Unit

  def engineSetKeyEntry(
      alias: String,
      key: Array[Byte],
      chain: Array[Certificate]
  ): Unit

  def engineSetCertificateEntry(alias: String, cert: Certificate): Unit

  def engineDeleteEntry(alias: String): Unit

  def engineAliases(): Enumeration[String]

  def engineContainsAlias(alias: String): Boolean

  def engineSize(): Int

  def engineIsKeyEntry(alias: String): Boolean

  def engineIsCertificateEntry(alias: String): Boolean

  def engineGetCertificateAlias(cert: Certificate): String

  def engineStore(stream: OutputStream, password: Array[Char]): Unit

  def engineStore(param: KeyStore.LoadStoreParameter): Unit = {
    ???
  }

  def engineLoad(stream: InputStream, password: Array[Char]): Unit

  def engineLoad(param: KeyStore.LoadStoreParameter): Unit = {
    ???
  }

  // @since JDK 18
  def engineGetAttributes(alias: String): JSet[KeyStore.Entry.Attribute] = {
    if (!engineContainsAlias(alias)) return JSet.of()
    ???
  }

  def engineGetEntry(
      alias: String,
      protParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry = {
    ???
  }

  def engineSetEntry(
      alias: String,
      entry: KeyStore.Entry,
      protParam: KeyStore.ProtectionParameter
  ): Unit = {
    ???
  }

  def engineEntryInstanceOf(
      alias: String,
      entryClass: Class[_ <: KeyStore.Entry]
  ): Boolean = {
    ???
  }

  def engineProbe(stream: InputStream): Boolean = {
    ???
  }
}
