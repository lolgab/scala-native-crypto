package com.github.lolgab.scalanativecrypto

import java.security.Provider
import java.util.concurrent.atomic.AtomicBoolean
import java.util.{List => JList, Set => JSet, Map => JMap}
import java.util.Objects.requireNonNull
import java.util.concurrent.ConcurrentHashMap

import com.github.lolgab.scalanativecrypto.services._

class OpenSslProvider(
    private val name: String = "scala-native-crypto",
    private val versionStr: String = "0.1",
    private val info: String =
      "Java Cryptography Provider for Scala Native using OpenSSL"
) extends Provider(name, versionStr, info) {

  private val initialized: AtomicBoolean = new AtomicBoolean(false)

  // private var _entrySet: JSet[JMap.Entry[Object, Object]] = ???
  private val services: JMap[OpenSslProvider.ServiceKey, Provider.Service] =
    new ConcurrentHashMap()

  setup()

  override def configure(configArg: String): Provider =
    throw new UnsupportedOperationException(
      "Dynamic configuration is not supported yet"
    )

  override def isConfigured(): Boolean = initialized.getOpaque()

  override def getName(): String = name

  override def getVersionStr(): String = versionStr

  override def getInfo(): String = info

  override def getService(
      svc: String,
      algorithm: String
  ): Provider.Service = {
    if (!JcaService.names.contains(svc.toUpperCase()))
      throw new IllegalArgumentException(
        s"Unknown service: $svc, use one of ${JcaService.names.mkString(", ")}"
      )

    services.get(
      OpenSslProvider.ServiceKey(svc, algorithm)
    )
  }

  override def getServices(): JSet[Provider.Service] =
    JSet.of(
      services.values().toArray().map(_.asInstanceOf[Provider.Service]): _*
    )

  override protected def putService(svc: Provider.Service): Unit =
    services.put(
      OpenSslProvider.ServiceKey(svc.getType(), svc.getAlgorithm()),
      svc
    )

  private def putAliasService(svc: Provider.Service, alias: String): Unit =
    services.put(
      OpenSslProvider
        .ServiceKey(svc.getType(), alias, Some(svc.getAlgorithm())),
      svc
    )

  override protected def removeService(s: Provider.Service): Unit =
    services.remove(
      OpenSslProvider.ServiceKey(s.getType(), s.getAlgorithm())
    )

  private def setup(): Unit = {
    if (initialized.compareAndSet(false, true)) {

      for (
        (len, aliases) <- Seq(
          ("1", JList.of[String]("SHA", "SHA-1")),
          ("224", JList.of[String]("SHA-224")),
          ("256", JList.of[String]("SHA-256")),
          ("384", JList.of[String]("SHA-384")),
          ("512", JList.of[String]("SHA-512")),
          ("3-224", JList.of[String]()),
          ("3-256", JList.of[String]()),
          ("3-384", JList.of[String]()),
          ("3-512", JList.of[String]())
        )
      ) {
        val svc = OpenSslMacSerice(this, s"HmacSHA${len}", aliases, JMap.of())
        putService(svc)
        aliases.forEach(alias => putAliasService(svc, alias))
      }

      for (
        (algo, aliases) <- Seq(
          ("MD5", JList.of[String]()),
          ("SHA", JList.of[String]("SHA-1", "SHA1")),
          ("SHA-224", JList.of[String]("SHA224")),
          ("SHA-256", JList.of[String]("SHA256")),
          ("SHA-384", JList.of[String]("SHA384")),
          ("SHA-512", JList.of[String]("SHA512")),
          ("SHA3-224", JList.of[String]()),
          ("SHA3-256", JList.of[String]()),
          ("SHA3-384", JList.of[String]()),
          ("SHA3-512", JList.of[String]())
        )
      ) {
        val svc = OpenSslMessageDigestSerice(this, algo, aliases, JMap.of())
        putService(svc)
        aliases.forEach(alias => putAliasService(svc, alias))
      }

    }
  }
}

object OpenSslProvider {

  val defaultInstance = new OpenSslProvider()

  def apply(): OpenSslProvider = new OpenSslProvider()

  private case class ServiceKey(
      svc: String,
      algorithm: String,
      origAlgorithm: Option[String] = None
  ) {
    requireNonNull(svc)
    requireNonNull(algorithm)
    require(svc.nonEmpty && algorithm.nonEmpty)
    require(
      origAlgorithm.isEmpty || origAlgorithm.get.nonEmpty,
      "origAlgorithm name for an aliases, if provided, must be non-empty"
    )

    override def toString(): String = s"${svc}.${algorithm}"

    override def hashCode(): Int =
      31 * svc.toUpperCase().hashCode() + algorithm.toUpperCase().hashCode()

    override def equals(obj: Any): Boolean = {
      if (this eq obj.asInstanceOf[AnyRef]) return true
      if (!obj.isInstanceOf[ServiceKey]) return false

      val other = obj.asInstanceOf[ServiceKey]
      svc.equalsIgnoreCase(other.svc) && algorithm.equalsIgnoreCase(
        other.algorithm
      )
    }
  }
}
