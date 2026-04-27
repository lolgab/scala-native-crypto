package java.security

import java.io.{File, InputStream, OutputStream}
import java.security.spec.AlgorithmParameterSpec
// To avoid name conflict with `java.security.Certificate`
// or else the compiler will warn or even error for name hiding issue
import java.security.cert.{Certificate => CertCertificate}
import java.util.{Arrays, Collections, Date, Enumeration, Set => JSet}
import java.util.Objects.requireNonNull
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.SecretKey
import javax.security.auth.Destroyable
import javax.security.auth.callback.CallbackHandler

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyStoreSpi.html
abstract class KeyStoreSpi {

  def engineGetKey(alias: String, password: Array[Char]): Key

  def engineGetCertificateChain(alias: String): Array[CertCertificate]

  def engineGetCertificate(alias: String): CertCertificate

  def engineGetCreationDate(alias: String): Date

  def engineSetKeyEntry(
      alias: String,
      key: Key,
      password: Array[Char],
      chain: Array[CertCertificate]
  ): Unit

  def engineSetKeyEntry(
      alias: String,
      key: Array[Byte],
      chain: Array[CertCertificate]
  ): Unit

  def engineSetCertificateEntry(alias: String, cert: CertCertificate): Unit

  def engineDeleteEntry(alias: String): Unit

  def engineAliases(): Enumeration[String]

  def engineContainsAlias(alias: String): Boolean

  def engineSize(): Int

  def engineIsKeyEntry(alias: String): Boolean

  def engineIsCertificateEntry(alias: String): Boolean

  def engineGetCertificateAlias(cert: CertCertificate): String

  def engineStore(stream: OutputStream, password: Array[Char]): Unit

  def engineStore(param: KeyStore.LoadStoreParameter): Unit

  def engineLoad(stream: InputStream, password: Array[Char]): Unit

  def engineLoad(param: KeyStore.LoadStoreParameter): Unit

  // @since JDK 18
  def engineGetAttributes(alias: String): JSet[KeyStore.Entry.Attribute]

  def engineGetEntry(
      alias: String,
      protParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry

  def engineSetEntry(
      alias: String,
      entry: KeyStore.Entry,
      protParam: KeyStore.ProtectionParameter
  ): Unit

  def engineEntryInstanceOf(
      alias: String,
      entryClass: Class[_ <: KeyStore.Entry]
  ): Boolean

  // @since JDK 9
  def engineProbe(stream: InputStream): Boolean

}

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyStore.html
abstract class KeyStore(
    spi: KeyStoreSpi,
    provider: Provider,
    ksType: String
) {

  final def getProvider(): Provider = provider

  final def getType(): String = ksType

  // @since JDK 18
  final def getAttributes(alias: String): JSet[KeyStore.Entry.Attribute] =
    spi.engineGetAttributes(alias)

  final def getKey(alias: String, password: Array[Char]): Key =
    spi.engineGetKey(alias, password)

  final def getCertificateChain(alias: String): Array[CertCertificate] =
    spi.engineGetCertificateChain(alias)

  final def getCertificate(alias: String): CertCertificate =
    spi.engineGetCertificate(alias)

  final def getCreationDate(alias: String): Date =
    spi.engineGetCreationDate(alias)

  final def setKeyEntry(
      alias: String,
      key: Key,
      password: Array[Char],
      chain: Array[CertCertificate]
  ): Unit =
    spi.engineSetKeyEntry(alias, key, password, chain)

  final def setKeyEntry(
      alias: String,
      key: Array[Byte],
      chain: Array[CertCertificate]
  ): Unit =
    spi.engineSetKeyEntry(alias, key, chain)

  final def setCertificateEntry(alias: String, cert: CertCertificate): Unit =
    spi.engineSetCertificateEntry(alias, cert)

  final def deleteEntry(alias: String): Unit =
    spi.engineDeleteEntry(alias)

  final def aliases(): Enumeration[String] =
    spi.engineAliases()

  final def containsAlias(alias: String): Boolean =
    spi.engineContainsAlias(alias)

  final def size(): Int =
    spi.engineSize()

  final def isKeyEntry(alias: String): Boolean =
    spi.engineIsKeyEntry(alias)

  final def isCertificateEntry(alias: String): Boolean =
    spi.engineIsCertificateEntry(alias)

  final def getCertificateAlias(cert: CertCertificate): String =
    spi.engineGetCertificateAlias(cert)

  final def store(stream: OutputStream, password: Array[Char]): Unit =
    spi.engineStore(stream, password)

  final def store(param: KeyStore.LoadStoreParameter): Unit =
    spi.engineStore(param)

  final def load(stream: InputStream, password: Array[Char]): Unit =
    spi.engineLoad(stream, password)

  final def load(param: KeyStore.LoadStoreParameter): Unit =
    spi.engineLoad(param)

  final def getEntry(
      alias: String,
      protParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry =
    spi.engineGetEntry(alias, protParam)

  final def setEntry(
      alias: String,
      entry: KeyStore.Entry,
      protParam: KeyStore.ProtectionParameter
  ): Unit =
    spi.engineSetEntry(alias, entry, protParam)

  final def entryInstanceOf(
      alias: String,
      entryClass: Class[_ <: KeyStore.Entry]
  ): Boolean =
    spi.engineEntryInstanceOf(alias, entryClass)

}

object KeyStore {

  import com.github.lolgab.scalanativecrypto.{OpenSSLProvider, JcaService}

  def getInstance(ksType: String): KeyStore =
    getInstance(ksType, OpenSSLProvider.defaultInstance)

  def getInstance(ksType: String, provider: String): KeyStore =
    throw new UnsupportedOperationException()

  def getInstance(ksType: String, provider: Provider): KeyStore = {
    requireNonNull(ksType)
    requireNonNull(provider)
    require(!ksType.isEmpty())

    val service = provider.getService(JcaService.KeyStore.name, ksType)
    if (service == null)
      throw new NoSuchAlgorithmException(
        s"Algorithm ${ksType} not found in provider ${provider.getName()}"
      )
    service.newInstance(null).asInstanceOf[KeyStore]
  }

  def getDefaultType(): String =
    "PKCS12"

  def getInstance(file: File, password: Array[Char]): KeyStore =
    ???

  def getInstance(file: File, param: LoadStoreParameter): KeyStore =
    ???

  //
  // Nested class Builder
  //

  abstract class Builder protected (ks: KeyStore, pp: ProtectionParameter) {
    final def getKeyStore(): KeyStore = ks
    def getProtectionParameter(alias: String): ProtectionParameter
  }

  object Builder {
    def newInstance(
        keyStore: KeyStore,
        protectionParameter: ProtectionParameter
    ): Builder = {
      requireNonNull(keyStore)
      requireNonNull(protectionParameter)

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
      requireNonNull(ksType)
      requireNonNull(protection)
      requireNonNull(provider)
      require(!ksType.isEmpty())
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
      if (destroyed.getOpaque())
        throw new IllegalStateException("password has been cleared")
      _password
    }

    override def destroy(): Unit =
      if (destroyed.compareAndSet(false, true))
        Arrays.fill(_password, ' ')

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
      private val chain: Array[CertCertificate],
      private val attributes: JSet[Entry.Attribute]
  ) extends Entry {

    requireNonNull(privateKey)
    requireNonNull(chain)
    requireNonNull(attributes)
    require(chain.length > 0)

    private lazy val _chain: Array[CertCertificate] = chain.clone()
    private lazy val _attributes: JSet[Entry.Attribute] =
      Collections.unmodifiableSet(attributes)

    def this(privateKey: PrivateKey, chain: Array[CertCertificate]) =
      this(privateKey, chain, JSet.of())

    def getPrivateKey(): PrivateKey = privateKey

    def getCertificateChain(): Array[CertCertificate] = _chain

    def getCertificate(): CertCertificate = _chain(0)

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
      trustedCert: CertCertificate,
      attributes: JSet[Entry.Attribute]
  ) extends Entry {

    requireNonNull(trustedCert)
    requireNonNull(attributes)

    private lazy val _attributes: JSet[Entry.Attribute] =
      Collections.unmodifiableSet(attributes)

    def this(trustedCert: CertCertificate) = this(trustedCert, JSet.of())

    def getTrustedCertificate(): CertCertificate = trustedCert

    def getAttributes(): JSet[Entry.Attribute] = _attributes

    override def toString(): String =
      s"Trusted certificate entry:\n${trustedCert.toString()}"
  }

}
