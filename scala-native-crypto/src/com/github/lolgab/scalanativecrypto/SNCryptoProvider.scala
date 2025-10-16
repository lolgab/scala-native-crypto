package com.github.lolgab.scalanativecrypto.internal.security

import java.security.Provider
import java.util.concurrent.atomic.AtomicBoolean
import java.util.{Set => JSet, Map => JMap}
import java.util.Objects.requireNonNull
import java.util.concurrent.ConcurrentHashMap

class SNCryptoProvider(
    private val name: String = "scala-native-crypto",
    private val versionStr: String = "0.1",
    private val info: String =
      "Java Cryptography Provider for Scala Native using OpenSSL"
) extends Provider(name, versionStr, info) {

  private val initialized: AtomicBoolean = new AtomicBoolean(false)

  private var _entrySet: JSet[JMap.Entry[Object, Object]] = ???
  private val services: JMap[SNCryptoProvider.ServiceKey, Provider.Service] =
    new ConcurrentHashMap()

  override def configure(configArg: String): Provider = ???

  override def isConfigured(): Boolean = ???

  override def getName(): String = name

  override def getVersionStr(): String = versionStr

  override def getInfo(): String = info

  override def getService(`type`: String, algorithm: String): Provider.Service =
    services.get(SNCryptoProvider.ServiceKey(`type`, algorithm))

  override def getServices(): JSet[Provider.Service] =
    JSet.of(
      services.values().toArray().map(_.asInstanceOf[Provider.Service]): _*
    )

  override protected def putService(s: Provider.Service): Unit = ???

  override protected def removeService(s: Provider.Service): Unit = ???

}

object SNCryptoProvider {
  def apply(): SNCryptoProvider = new SNCryptoProvider()

  private case class ServiceKey(`type`: String, algorithm: String) {
    requireNonNull(`type`)
    requireNonNull(algorithm)
    require(`type`.nonEmpty && algorithm.nonEmpty)

    override def toString(): String = s"${`type`}.${algorithm}"

    override def hashCode(): Int =
      31 * `type`.toUpperCase().hashCode() + algorithm.toUpperCase().hashCode()

    override def equals(obj: Any): Boolean = {
      if (this eq obj.asInstanceOf[AnyRef]) return true
      if (!obj.isInstanceOf[ServiceKey]) return false

      val other = obj.asInstanceOf[ServiceKey]

      `type`.equalsIgnoreCase(other.`type`) &&
      algorithm.equalsIgnoreCase(other.algorithm)
    }
  }
}
