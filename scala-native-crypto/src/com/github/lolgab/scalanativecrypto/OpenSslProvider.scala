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

  private var _entrySet: JSet[JMap.Entry[Object, Object]] = ???
  private val services: JMap[OpenSslProvider.ServiceKey, Provider.Service] =
    new ConcurrentHashMap()

  override def configure(configArg: String): Provider = ???

  override def isConfigured(): Boolean = ???

  override def getName(): String = name

  override def getVersionStr(): String = versionStr

  override def getInfo(): String = info

  override def getService(
      svc: String,
      algorithm: String
  ): Provider.Service = {
    if (!JcaService.allNames.contains(svc.toUpperCase()))
      throw new IllegalArgumentException(
        s"Unknown service: $svc, use one of ${JcaService.allNames.mkString(", ")}"
      )

    services.get(
      OpenSslProvider.ServiceKey(svc.asInstanceOf[JcaService], algorithm)
    )
  }

  override def getServices(): JSet[Provider.Service] =
    JSet.of(
      services.values().toArray().map(_.asInstanceOf[Provider.Service]): _*
    )

  override protected def putService(s: Provider.Service): Unit = ???

  override protected def removeService(s: Provider.Service): Unit = ???

}

object OpenSslProvider {

  val defaultInstance = new OpenSslProvider()

  def apply(): OpenSslProvider = new OpenSslProvider()

  private case class ServiceKey(svc: JcaService, algorithm: String) {
    requireNonNull(svc)
    requireNonNull(algorithm)
    require(svc.name.nonEmpty && algorithm.nonEmpty)

    override def toString(): String = s"${svc.name}.${algorithm}"

    override def hashCode(): Int =
      31 * svc.name.toUpperCase().hashCode() + algorithm
        .toUpperCase()
        .hashCode()

    override def equals(obj: Any): Boolean = {
      if (this eq obj.asInstanceOf[AnyRef]) return true
      if (!obj.isInstanceOf[ServiceKey]) return false

      val other = obj.asInstanceOf[ServiceKey]

      svc.name.equalsIgnoreCase(other.svc.name) &&
      algorithm.equalsIgnoreCase(other.algorithm)
    }
  }
}
