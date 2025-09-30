package java.security

import java.util.{Map => JMap, Set => JSet, List => JList}
import java.util.{Collections, Properties}
import java.util.Objects.requireNonNull

// Refs:
// 1. https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/Provider.html
// 2. https://docs.oracle.com/en/java/javase/24/security/howtoimplaprovider.html
abstract class Provider(
    private val name: String,
    private val versionStr: String,
    private val info: String
) extends Properties {

  requireNonNull(name)
  requireNonNull(versionStr)
  requireNonNull(info)
  require(name.nonEmpty && versionStr.nonEmpty && info.nonEmpty)

  // @volatile protected val defaults = _

  // @deprecated since JDK 9
  // def this(name: String, version: Double, info: String)

  // @since JDK 9
  def configure(configArg: String): Provider

  // @since JDK 9
  def isConfigured(): Boolean

  def getName(): String

  // @deprecated since JDK 9
  // def getVersion(): Double = version

  // @since JDK 9
  def getVersionStr(): String

  def getInfo(): String

  override def toString(): String = s"${name} version ${versionStr}"

  def load(input: InputStream): Unit

  def getService(`type`: String, algorithm: String): Provider.Service

  def getServices(): JSet[Provider.Service]

  protected def putService(s: Provider.Service): Unit

  protected def removeService(s: Provider.Service): Unit

}

object Provider {

  private case class ServiceKey(`type`: String, algorithm: String) {
    requireNonNull(`type`)
    requireNonNull(algorithm)
    require(`type`.nonEmpty && algorithm.nonEmpty)

    override def toString(): String = s"${`type`}.${algorithm}"

    // should be case insensitive
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

  class Service(
      private val provider: Provider,
      private val svcType: String,
      private val algorithm: String,
      private val className: String,
      private val aliases: JList[String],
      private val attributes: JMap[String, String]
  ) {
    requireNonNull(provider)
    requireNonNull(svcType)
    requireNonNull(algorithm)
    requireNonNull(className)
    require(svcType.nonEmpty && algorithm.nonEmpty && className.nonEmpty)

    private val svcAliases: JList[String] =
      if (aliases == null) JList.of()
      else Collections.unmodifiableList(aliases)
    private val serviceAttributes: JMap[String, String] =
      if (attributes == null) JMap.of()
      else Collections.unmodifiableMap(attributes)

    final def getType(): String = svcType

    final def getAlgorithm(): String = algorithm

    final def getProvider(): Provider = provider

    final def getClassName(): String = className

    final def getAttribute(name: String): String = {
      requireNonNull(name)
      require(name.nonEmpty)
      serviceAttributes.get(name)
    }

    def newInstance(constructorParameter: Object): Object = ???

    def supportsParameter(parameter: Object): Boolean = ???

    override def toString(): String = {
      val aliasStr =
        if (svcAliases.isEmpty) ""
        else s"  aliases: ${svcAliases}\r\n"
      val attrStr =
        if (serviceAttributes.isEmpty) ""
        else s"  attributes: ${serviceAttributes}\r\n"

      s"${provider.getName()}: ${svcType}.${algorithm} -> ${className}\r\n${aliasStr}${attrStr}"
    }
  }
}
