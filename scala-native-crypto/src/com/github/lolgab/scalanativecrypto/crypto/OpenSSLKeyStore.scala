package com.github.lolgab.scalanativecrypto.crypto

import java.io.{InputStream, OutputStream}
import java.io.IOException
import java.security.{Key, Provider, KeyStore, KeyStoreSpi}
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.util.{Date, Enumeration, Set => JSet}
import java.util.Objects.requireNonNull
import java.util.concurrent.atomic.AtomicBoolean
import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer

import scala.scalanative.unsafe.{Ptr, Zone, toCString, alloc, stackalloc}
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.annotation.alwaysinline

import com.github.lolgab.scalanativecrypto.internal.crypto
import com.github.lolgab.scalanativecrypto.internal.crypto.{
  PKCS12_*,
  X509_*,
  EVP_PKEY_*,
  stack_st_X509
}
import java.security.KeyStoreException

final class OpenSSLKeyStore(provider: Provider, ksType: String)
    extends KeyStore(new OpenSSLKeyStoreSpi(), provider, ksType)

final class OpenSSLKeyStoreSpi protected[scalanativecrypto]
    extends KeyStoreSpi {

  val isLoaded = new AtomicBoolean(false)

  var pkey: EVP_PKEY_* = null
  var pkcs: PKCS12_* = null
  var x509: X509_* = null
  var stackOfX509: Ptr[stack_st_X509] = null

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_EVP_PKEY(this, pkey)
    CtxFinalizer.register_PKCS12(this, pkcs)
    CtxFinalizer.register_X509(this, x509)
    CtxFinalizer.register_StackOfX509(this, stackOfX509)
  } else {
    System.err.println(
      "[java.security.KeyStore] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  override def engineGetKey(alias: String, password: Array[Char]): Key = {
    throwIfNotLoaded()
    ???
  }

  override def engineGetCertificateChain(alias: String): Array[Certificate] = {
    throwIfNotLoaded()
    ???
  }

  override def engineGetCertificate(alias: String): Certificate = {
    throwIfNotLoaded()
    ???
  }

  override def engineGetCreationDate(alias: String): Date = {
    throwIfNotLoaded()
    ???
  }

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

  override def engineDeleteEntry(alias: String): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineAliases(): Enumeration[String] = {
    throwIfNotLoaded()
    ???
  }

  override def engineContainsAlias(alias: String): Boolean = {
    throwIfNotLoaded()
    ???
  }

  override def engineSize(): Int = {
    throwIfNotLoaded()
    val n = crypto.sncrypto_ossl_sk_X509_num(stackOfX509)
    if (n < 0) 0 else n
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
    requireNonNull(stream, "the InputStream must be non-null")
    requireNonNull(password, "the password must be non-null")

    if (!isLoaded.compareAndExchange(false, true))
      throw new IOException("the KeyStore has already been loaded")
    else {
      if (stream.markSupported()) stream.mark(stream.available() + 1)

      val bytes = stream.readAllBytes()
      if (bytes.isEmpty)
        throw new IOException("the InputStream is empty")

      Zone.acquire { implicit zone =>
        val memBuf = alloc[Byte](bytes.length)
        for (i <- bytes.indices) memBuf(i) = bytes(i)

        val passwdBuf = toCString(password.mkString)

        val bio = crypto.BIO_new_mem_buf(memBuf, bytes.length)
        try {
          val p12Handle = crypto.d2i_PKCS12_bio(bio, null)
          if (p12Handle == null)
            throw new IOException("failed to parse the PKCS#12 data")

          val _pkey = stackalloc[EVP_PKEY_*]()
          val _x509 = stackalloc[X509_*]()
          val _stackOfX509 = stackalloc[Ptr[stack_st_X509]]()

          val verified =
            crypto.PKCS12_verify_mac(p12Handle, passwdBuf, password.length)
          if (verified == 0)
            throw new IOException(
              "failed to verify the PKCS#12 data",
              new UnrecoverableKeyException(
                "the provided password is incorrect"
              )
            )

          val ret = crypto.PKCS12_parse(
            p12Handle,
            passwdBuf,
            _pkey,
            _x509,
            _stackOfX509
          )
          if (ret == 0) {
            // fetch error via ERR_get_error
            throw new CertificateException("failed to parse the PKCS#12 data")
          }

          pkcs = p12Handle
          pkey = !_pkey
          x509 = !_x509
          stackOfX509 = !_stackOfX509
        } finally {
          crypto.BIO_free(bio)
        }
      }
    }
  }

  override def engineLoad(param: KeyStore.LoadStoreParameter): Unit = {
    requireNonNull(
      param,
      "the param (KeyStore.LoadStoreParameter) must be non-null"
    )

    if (!isLoaded.compareAndExchange(false, true))
      throw new IOException("the KeyStore has already been loaded")
    else {
      ???
    }
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
      protParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()
    ???
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
  def throwIfNotLoaded(): Unit =
    if (!isLoaded.getOpaque())
      throw new KeyStoreException(
        "the keystore has not been initialized (loaded)."
      )

}
