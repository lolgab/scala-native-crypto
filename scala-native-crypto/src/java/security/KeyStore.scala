package java.security

import java.io.{
  InputStream,
  OutputStream,
  DataInputStream,
  BufferedInputStream,
  File,
  FileInputStream
}
import java.io.IOException

import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.security.{NoSuchAlgorithmException, NoSuchProviderException}
import java.util.{Arrays, Collections, Date, Enumeration}
import java.util.{Set => JSet}
import java.util.Objects.requireNonNull
import java.util.concurrent.atomic.AtomicBoolean

import javax.crypto.SecretKey
import javax.security.auth.{Destroyable}
import javax.security.auth.callback.CallbackHandler

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html
abstract class KeyStore(
    // private val ksSpi: KeyStoreSpi,
    private val provider: Provider,
    private val ksType: String
) {

  private val _initialized: AtomicBoolean = new AtomicBoolean(false)

  final def getProvider(): Provider = provider

  final def getType(): String = ksType

  // @since JDK 18
  def getAttributes(alias: String): JSet[KeyStore.Entry.Attribute]

  def getKey(alias: String, password: Array[Char]): Key

  def getCertificateChain(alias: String): Array[Certificate]

  def getCertificate(alias: String): Certificate

  def getCreationDate(alias: String): Date

  def setKeyEntry(
      alias: String,
      key: Key,
      password: Array[Char],
      chain: Array[Certificate]
  ): Unit

  def setKeyEntry(
      alias: String,
      key: Array[Byte],
      chain: Array[Certificate]
  ): Unit

  def setCertificateEntry(alias: String, cert: Certificate): Unit

  def deleteEntry(alias: String): Unit

  def aliases(): Enumeration[String]

  def containsAlias(alias: String): Boolean

  def size(): Int

  def isKeyEntry(alias: String): Boolean

  def isCertificateEntry(alias: String): Boolean

  def getCertificateAlias(cert: Certificate): String

  def store(stream: OutputStream, password: Array[Char]): Unit

  def store(param: KeyStore.LoadStoreParameter): Unit

  def load(stream: InputStream, password: Array[Char]): Unit

  def load(param: KeyStore.LoadStoreParameter): Unit

  def getEntry(
      alias: String,
      protParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry

  def setEntry(
      alias: String,
      entry: KeyStore.Entry,
      protParam: KeyStore.ProtectionParameter
  ): Unit

  def entryInstanceOf(
      alias: String,
      entryClass: Class[_ <: KeyStore.Entry]
  ): Boolean

}

object KeyStore {

  def getInstance(ksType: String): KeyStore = {
    requireNonNull(ksType)

    ???
  }

  def getInstance(ksType: String, provider: String): KeyStore = {
    requireNonNull(ksType)
    requireNonNull(provider)
    require(provider.nonEmpty)

    ???
  }

  def getInstance(ksType: String, provider: Provider): KeyStore = {
    requireNonNull(ksType)
    requireNonNull(provider)

    ???
  }

  def getDefaultType(): String = {
    // val kstype = Security.getProperty(KEYSTORE_TYPE)
    // if (kstype == null) "pkcs12" else kstype
    ???
  }

  def getInstance(file: File, password: Array[Char]): KeyStore = ???

  def getInstance(file: File, param: LoadStoreParameter): KeyStore = ???

  //
  // Nested class Builder
  //

  abstract class Builder protected (ks: KeyStore, pp: ProtectionParameter) {
    def getKeyStore(): KeyStore = ks
    def getProtectionParameter(alias: String): ProtectionParameter
  }

  object Builder {
    def newInstance(
        keyStore: KeyStore,
        protectionParameter: ProtectionParameter
    ): Builder = {
      requireNonNull(keyStore)
      requireNonNull(protectionParameter)
      require(keyStore._initialized.get())

      ???
    }

    def newInstance(
        ksType: String,
        provider: Provider,
        file: File,
        protection: ProtectionParameter
    ): Builder = {
      requireNonNull(ksType)
      requireNonNull(provider)
      requireNonNull(file)
      requireNonNull(protection)
      require(
        protection.isInstanceOf[PasswordProtection] || protection
          .isInstanceOf[CallbackHandlerProtection],
        "protection must be PasswordProtection or CallbackHandlerProtection"
      )
      require(file.isFile(), "file does not exist or is not a regular file")

      ???
    }

    def newInstance(file: File, protection: ProtectionParameter): Builder = {
      requireNonNull(file)
      requireNonNull(protection)
      require(
        protection.isInstanceOf[PasswordProtection] || protection
          .isInstanceOf[CallbackHandlerProtection],
        "protection must be PasswordProtection or CallbackHandlerProtection"
      )
      require(file.isFile(), "file does not exist or is not a regular file")

      ???
    }

    def newInstance(
        ksType: String,
        provider: Provider,
        protection: ProtectionParameter
    ): Builder = {
      requireNonNull(protection)
      requireNonNull(provider)
      require(
        protection.isInstanceOf[PasswordProtection] || protection
          .isInstanceOf[CallbackHandlerProtection],
        "protection must be PasswordProtection or CallbackHandlerProtection"
      )

      ???
    }
  }

  //
  // Nested class LoadStoreParameter
  //

  abstract class LoadStoreParameter {
    def getProtectionParameter(): ProtectionParameter
  }

  //
  // Nested class `ProtectionParameter`
  // and its subclasses `CallbackHandlerProtection`, `PasswordProtection`
  //

  abstract class ProtectionParameter

  class CallbackHandlerProtection(handler: CallbackHandler)
      extends ProtectionParameter {
    requireNonNull(handler)
    def getCallbackHandler(): CallbackHandler = handler
  }

  class PasswordProtection(
      password: Array[Char],
      protectionAlgorithm: String,
      protectionParameters: AlgorithmParameterSpec
  ) extends ProtectionParameter
      with Destroyable {

    requireNonNull(password)
    require(
      protectionAlgorithm == null || protectionAlgorithm.nonEmpty,
      "protectionAlgorithm could be null otherwise cannot be empty if not null"
    )

    private lazy val _password: Array[Char] = password.clone()
    private val destroyed: AtomicBoolean = new AtomicBoolean(false)

    def this(password: Array[Char]) = this(password, null, null)

    def getProtectionAlgorithm(): String = protectionAlgorithm

    def getProtectionParameters(): AlgorithmParameterSpec = protectionParameters

    def getPassword(): Array[Char] = {
      if (destroyed.get())
        throw new IllegalStateException("password has been cleared")
      _password
    }

    override def destroy(): Unit = {
      Arrays.fill(_password, ' ')
      destroyed.compareAndSet(false, true)
    }

    override def isDestroyed(): Boolean = destroyed.getOpaque()
  }

  //
  // Nested class `Entry`
  // and its subclasses `PrivateKeyEntry`, `SecretKeyEntry`, `TrustedCertificateEntry`
  //

  abstract class Entry { def getAttributes(): JSet[Entry.Attribute] }
  object Entry {
    abstract class Attribute {
      def getName(): String
      def getValue(): String
    }
  }

  final class PrivateKeyEntry(
      private val privateKey: PrivateKey,
      private val chain: Array[Certificate],
      private val attributes: JSet[Entry.Attribute]
  ) extends Entry {

    requireNonNull(privateKey)
    requireNonNull(chain)
    requireNonNull(attributes)
    require(chain.length > 0)

    private lazy val _chain: Array[Certificate] = chain.clone()
    private lazy val _attributes: JSet[Entry.Attribute] =
      Collections.unmodifiableSet(attributes)

    def this(privateKey: PrivateKey, chain: Array[Certificate]) =
      this(privateKey, chain, JSet.of())

    def getPrivateKey(): PrivateKey = privateKey

    def getCertificateChain(): Array[Certificate] = _chain

    def getCertificate(): Certificate = _chain(0)

    def getAttributes(): JSet[Entry.Attribute] = _attributes

    override def toString(): String = {
      val perCert = _chain.map(_.toString()).mkString("\n")
      s"Private key entry and certificate chain with ${_chain.length} elements:\n${perCert}"
    }
  }

  final class SecretKeyEntry(
      secretKey: SecretKey,
      attributes: JSet[Entry.Attribute]
  ) extends Entry {

    requireNonNull(secretKey)
    requireNonNull(attributes)

    private lazy val _attributes: JSet[Entry.Attribute] =
      Collections.unmodifiableSet(attributes)

    def this(secretKey: SecretKey) = this(secretKey, JSet.of())

    def getSecretKey(): SecretKey = secretKey

    def getAttributes(): JSet[Entry.Attribute] = _attributes

    override def toString(): String =
      s"Secret key entry with algorithm ${secretKey.getAlgorithm()}"
  }

  final class TrustedCertificateEntry(
      trustedCert: Certificate,
      attributes: JSet[Entry.Attribute]
  ) extends Entry {

    requireNonNull(trustedCert)
    requireNonNull(attributes)

    private lazy val _attributes: JSet[Entry.Attribute] =
      Collections.unmodifiableSet(attributes)

    def this(trustedCert: Certificate) = this(trustedCert, JSet.of())

    def getTrustedCertificate(): Certificate = trustedCert

    def getAttributes(): JSet[Entry.Attribute] = _attributes

    override def toString(): String =
      s"Trusted certificate entry:\n${trustedCert.toString()}"
  }

}
