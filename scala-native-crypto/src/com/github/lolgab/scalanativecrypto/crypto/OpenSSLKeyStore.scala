package com.github.lolgab.scalanativecrypto.crypto

import java.io.{InputStream, OutputStream}
import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.security.{Key, Provider, KeyStore, KeyStoreSpi}
import java.security.{UnrecoverableKeyException, KeyStoreException}
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.util.{Date, Enumeration, Collections}
import java.util.{Set => JSet}
import java.util.Objects.requireNonNull
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer

import scala.scalanative.unsafe.{
  Ptr,
  Zone,
  alloc,
  fromCString,
  fromCStringSlice,
  stackalloc,
  toCString
}
import scala.scalanative.unsigned.UnsignedRichInt
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.annotation.alwaysinline

import com.github.lolgab.scalanativecrypto.AppLibCtx
import com.github.lolgab.scalanativecrypto.crypto.cert.OpenSSLX509Certificate
import com.github.lolgab.scalanativecrypto.internal.crypto
import com.github.lolgab.scalanativecrypto.internal.crypto.{
  PKCS12_*,
  X509_*,
  EVP_PKEY_*,
  stack_st_X509
}
import com.github.lolgab.scalanativecrypto.internal.Constants.NID_pkcs7_data

final class OpenSSLKeyStore protected[scalanativecrypto] (
    _spi: OpenSSLKeyStoreSpi,
    provider: Provider,
    ksType: String
) extends KeyStore(_spi, provider, ksType) {
  def pkey: EVP_PKEY_* = _spi.pkey
  def pkcs: PKCS12_* = _spi.pkcs
  def cert: X509_* = _spi.cert
  def stackOfCA: Ptr[stack_st_X509] = _spi.stackOfCA
}

private[scalanativecrypto] final class OpenSSLKeyStoreSpi protected[scalanativecrypto]
    extends KeyStoreSpi {

  @volatile
  private[scalanativecrypto] var pkey: EVP_PKEY_* = null
  @volatile
  private[scalanativecrypto] var pkcs: PKCS12_* = null
  @volatile
  private[scalanativecrypto] var cert: X509_* = null
  @volatile
  private[scalanativecrypto] var stackOfCA: Ptr[stack_st_X509] = null

  private val isLoaded = new AtomicBoolean(false)
  private val ptrLock = new ReentrantLock()

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_EVP_PKEY(this, pkey)
    CtxFinalizer.register_PKCS12(this, pkcs)
    CtxFinalizer.register_X509(this, cert)
    CtxFinalizer.register_StackOfX509(this, stackOfCA)
  } else {
    System.err.println(
      "[java.security.KeyStore] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  override def engineGetKey(alias: String, password: Array[Char]): Key = {
    throwIfNotLoaded()
    if (!engineContainsAlias(alias))
      null
    else {
      ???
    }
  }

  // Implement details: Always returns a copy of the certificate chain
  override def engineGetCertificateChain(alias: String): Array[Certificate] = {
    throwIfNotLoaded()
    if (!engineContainsAlias(alias))
      null
    else
      buildX509Chain(cert, stackOfCA).asInstanceOf[Array[Certificate]]
  }

  // Implement details: Always returns a copy of the certificate
  override def engineGetCertificate(alias: String): Certificate = {
    throwIfNotLoaded()
    val chain = engineGetCertificateChain(alias)
    if (chain != null && !chain.isEmpty) chain(0) else null
  }

  override def engineGetCreationDate(alias: String): Date = {
    throwIfNotLoaded()

    if (!engineContainsAlias(alias))
      null
    else {
      ???
    }
  }

  override def engineSetKeyEntry(
      alias: String,
      key: Key,
      password: Array[Char],
      chain: Array[Certificate]
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineSetKeyEntry(
      alias: String,
      key: Array[Byte],
      chain: Array[Certificate]
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineSetCertificateEntry(
      alias: String,
      cert: Certificate
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineDeleteEntry(alias: String): Unit = {
    throwIfNotLoaded()
    ???
  }

  // TODO:
  //
  // This will copy the alias string every time when invoked.
  // We can optimize this by caching the alias in a field when loading the KeyStore.
  // But don't forget that KeyStore can be reloaded when refactoring the code in the future.
  override def engineAliases(): Enumeration[String] = {
    throwIfNotLoaded()

    if (cert == null)
      Collections.emptyEnumeration()
    else {
      val alias = getX509Alias(cert)
      if (alias.isEmpty())
        Collections.emptyEnumeration()
      else
        Collections.enumeration(Collections.singletonList(alias))
    }
  }

  override def engineContainsAlias(alias: String): Boolean = {
    throwIfNotLoaded()
    var contains = false
    val aliases = engineAliases()
    while (aliases.hasMoreElements() && !contains) {
      val each = aliases.nextElement()
      if (each == alias)
        contains = true
    }
    contains
  }

  override def engineSize(): Int = {
    throwIfNotLoaded()
    if (cert != null) 1 else 0
  }

  override def engineIsKeyEntry(alias: String): Boolean = {
    throwIfNotLoaded()
    ???
  }

  override def engineIsCertificateEntry(alias: String): Boolean = {
    throwIfNotLoaded()
    ???
  }

  override def engineGetCertificateAlias(cert: Certificate): String = {
    throwIfNotLoaded()
    ???
  }

  override def engineStore(
      stream: OutputStream,
      password: Array[Char]
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineStore(param: KeyStore.LoadStoreParameter): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineLoad(stream: InputStream, password: Array[Char]): Unit = {
    if (stream == null)
      throw new NotImplementedError(
        "Creating an empty KeyStore or loading from null InputStream is not supported yet"
      )

    isLoaded.compareAndExchange(false, true)
    loadFromStream(
      stream,
      if (password == null) Array.emptyCharArray else password
    )
  }

  override def engineLoad(param: KeyStore.LoadStoreParameter): Unit = {
    requireNonNull(
      param,
      "the param (KeyStore.LoadStoreParameter) must be non-null"
    )
    ???
  }

  // @since JDK 18
  override def engineGetAttributes(
      alias: String
  ): JSet[KeyStore.Entry.Attribute] = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()
    ???
  }

  override def engineGetEntry(
      alias: String,
      protectionParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry = {
    throwIfNotLoaded()
    requireNonNull(alias, "the alias must be non-null")

    if (!engineContainsAlias(alias))
      null
    else {
      // Via behavior tests, we can assume that
      // JVM would check curr pkcs12 contains alias first
      // then check the protection parameter
      if (protectionParam == null)
        throw new UnrecoverableKeyException(
          "the protection parameter must be non-null"
        )

      ???
      // if (protectionParam.isInstanceOf[KeyStore.PasswordProtection]) {
      //   val pp: KeyStore.PasswordProtection =
      //     protectionParam.asInstanceOf[KeyStore.PasswordProtection]
      //   val passwd = pp.getPassword()
      //   val algo = pp.getProtectionAlgorithm()
      //   ???
      // } else {
      //   throw new NotImplementedError(
      //     s"not implemented ProtectionParameter type: ${protectionParam.getClass.getName}"
      //   )
      // }
    }
  }

  override def engineSetEntry(
      alias: String,
      entry: KeyStore.Entry,
      protParam: KeyStore.ProtectionParameter
  ): Unit = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()
    ???
  }

  override def engineEntryInstanceOf(
      alias: String,
      entryClass: Class[_ <: KeyStore.Entry]
  ): Boolean = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()
    ???
  }

  // @since JDK 9
  override def engineProbe(stream: InputStream): Boolean =
    ???

  /*
   * Private helper methods
   */

  @alwaysinline
  private def throwIfNotLoaded(): Unit =
    if (!isLoaded.get())
      throw new KeyStoreException(
        "the keystore has not been initialized (loaded)."
      )

  /**
   * @param stream
   *   Cannot be null.
   * @param password
   *   Cannot be null, but can be empty.
   */
  @alwaysinline
  private def loadFromStream(
      stream: InputStream,
      password: Array[Char]
  ): Unit = {
    requireNonNull(stream, "the input stream must be non-null.")

    if (stream.markSupported()) stream.mark(stream.available() + 1)
    val bytes = stream.readAllBytes()
    if (bytes.isEmpty)
      throw new IOException("the InputStream is empty")

    Zone.acquire { implicit zone =>
      val memBuf = alloc[Byte](bytes.length)
      for (i <- bytes.indices) memBuf(i) = bytes(i)

      // As OpenSSL Docs:
      // > The parameter pass is interpreted as a string in the UTF-8 encoding.
      // > If it is not valid UTF-8, then it is assumed to be ISO8859-1 instead.
      val passwdUTF8 = new String(password)
      val passwdLength = passwdUTF8.getBytes(UTF_8).length
      val passwdBuf = toCString(passwdUTF8)

      val p12_ = stackalloc[PKCS12_*]()
      !p12_ = crypto.PKCS12_init_ex(NID_pkcs7_data, AppLibCtx.osslLibCtx, null)

      val bio = crypto.BIO_new_mem_buf(memBuf, bytes.length)
      try {
        val p12Handle = crypto.d2i_PKCS12_bio(bio, p12_)
        if (p12Handle == null)
          throw new IOException("failed to parse the PKCS#12 data")

        val verified =
          crypto.PKCS12_verify_mac(p12Handle, passwdBuf, passwdLength)
        if (verified == 0)
          throw new IOException(
            "failed to verify the PKCS#12 data",
            new UnrecoverableKeyException(
              "the provided password is incorrect"
            )
          )

        val _pkey = stackalloc[EVP_PKEY_*]()
        val _x509 = stackalloc[X509_*]()
        val _stackOfX509 = stackalloc[Ptr[stack_st_X509]]()

        val ret = crypto.PKCS12_parse(
          p12Handle,
          passwdBuf,
          _pkey,
          _x509,
          _stackOfX509
        )
        if (ret == 0) {
          val errCode = crypto.ERR_get_error()
          val buf = stackalloc[Byte](256)
          crypto.ERR_error_string(errCode, buf)
          val errMsg = fromCString(buf, UTF_8)
          throw new CertificateException(
            s"Failed to parse the PKCS#12 data. error code: ${errCode}, error message: ${errMsg}."
          )
        }

        ptrLock.lock()
        try {
          // Clean up previous state when re-loading a KeyStore instance
          if (stackOfCA != null) {
            val n = crypto.sncrypto_ossl_sk_X509_num(stackOfCA)
            if (n > 0) {
              0 until n foreach { i =>
                val x = crypto.sncrypto_ossl_sk_X509_value(stackOfCA, i)
                if (x != null) crypto.X509_free(x)
              }
            }
            crypto.sncrypto_ossl_sk_X509_free(stackOfCA)
            stackOfCA = null
          }
          if (cert != null) {
            crypto.X509_free(cert)
            cert = null
          }
          if (pkey != null) {
            crypto.EVP_PKEY_free(pkey)
            pkey = null
          }
          if (pkcs != null) {
            crypto.PKCS12_free(pkcs)
            pkcs = null
          }

          pkcs = p12Handle
          pkey = !_pkey
          cert = !_x509
          stackOfCA = !_stackOfX509
        } // force new line
        finally ptrLock.unlock()
      } // force new line
      finally {
        crypto.BIO_free(bio)
      }
    }
  }

  private def buildX509Chain(
      ptr: X509_*,
      ptrStackCA: Ptr[stack_st_X509]
  ): Array[OpenSSLX509Certificate] = {
    val numCA =
      if (ptrStackCA == null) //
        0
      else {
        val n = crypto.sncrypto_ossl_sk_X509_num(ptrStackCA)
        if (n < 0) 0 else n
      }
    val numCert = if (ptr != null) 1 else 0
    val total = numCert + numCA
    val chain = new Array[OpenSSLX509Certificate](total)

    if (ptr != null) {
      chain(0) = new OpenSSLX509Certificate(x509DupOrUpRefByCheckPurpose(ptr))
    }

    for (i <- 0 until numCA) {
      val each = crypto.sncrypto_ossl_sk_X509_value(ptrStackCA, i)
      chain(i + numCert) = new OpenSSLX509Certificate(
        x509DupOrUpRefByCheckPurpose(each)
      )
    }

    chain
  }

  @alwaysinline
  private def x509DupOrUpRefByCheckPurpose(ptr: X509_*): X509_* = {
    val dup = crypto.X509_dup(ptr)
    if (dup == null)
      throw new RuntimeException("failed to duplicate the X509 certificate")

    val check = crypto.X509_check_purpose(dup, -1, 0)
    // -1 an error condition has occurred, and means
    // the certificate cannot be duplicated or is not valid for some reason.
    if (check < 0) {
      crypto.X509_free(dup)
      crypto.X509_up_ref(ptr)
      ptr
    } else {
      dup
    }
  }

  private def getX509Alias(ptr: X509_*): String = {
    requireNonNull(ptr, "the certificate must be non-null")
    val pLen = stackalloc[Int]()
    val ptrUbyteName = crypto.X509_alias_get0(ptr, pLen)
    if ((!pLen) > 0 && ptrUbyteName != null) {
      val buffer = stackalloc[Byte](!pLen)
      for (i <- 0 until !pLen)
        !(buffer + i) = (!(ptrUbyteName + i)).toByte
      fromCStringSlice(buffer, (!pLen).toCSize, UTF_8)
    } else {
      "1" // Default alias
    }
  }

}
