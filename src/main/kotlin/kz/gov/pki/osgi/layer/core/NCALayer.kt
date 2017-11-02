package kz.gov.pki.osgi.layer.core

import org.apache.felix.framework.FrameworkFactory
import org.osgi.framework.Bundle
import org.osgi.framework.BundleException
import org.osgi.framework.Constants
import java.io.File
import java.nio.file.Paths
import java.net.URI
import java.util.zip.ZipFile
import java.security.Policy
import org.osgi.framework.BundleContext
import org.osgi.service.condpermadmin.ConditionalPermissionAdmin
import org.apache.felix.framework.security.SecurityConstants
import org.slf4j.LoggerFactory
import kotlin.jvm.JvmStatic
import java.util.PriorityQueue
import java.lang.IllegalArgumentException
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import org.apache.felix.framework.SecurityActivator
import org.apache.felix.log.Activator
import org.apache.felix.framework.util.FelixConstants
import kz.gov.pki.osgi.layer.core.FelixLogger
import java.security.Security
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.osgi.layer.api.BundleJSON
import kz.gov.pki.osgi.layer.api.NCALayerJSON
import org.osgi.framework.Version
import uk.org.lidalia.sysoutslf4j.context.SysOutOverSLF4J
import javax.swing.JOptionPane
import org.osgi.service.condpermadmin.ConditionalPermissionInfo
import org.osgi.service.condpermadmin.ConditionInfo
import org.osgi.service.permissionadmin.PermissionInfo
import java.security.AllPermission
import java.nio.file.StandardCopyOption

fun <T> loggerFor(clazz: Class<T>) = LoggerFactory.getLogger(clazz)
val CORE_BUNDLESDIR_PROP = "ncalayer.bundlesdir"
val CORE_VERSION_PROP = "ncalayer.version"
val CORE_OSNAME_PROP = "ncalayer.osname"
val CORE_LOCATION_PROP = "ncalayer.location"
val OSNAME = System.getProperty("os.name").toLowerCase().substringBefore(' ')
val LOCATION_URI = NCALayer::class.java.protectionDomain.codeSource.location.toURI()
val LOCATION = Paths.get(LOCATION_URI).toFile()
val USER_HOME = File(System.getProperty("user.home"))
val CURRENTOS = OSType.from(OSNAME)
val UPDATE_FILENAME = "ncalayer.der"
val CORE_VERSION = NCALayer::class.java.getPackage().implementationVersion ?: "1.0"

enum class OSType(val osname: String) {
	MACOS("mac"),
	WINDOWS("windows"),
	LINUX("linux");

	companion object {
		fun from(osname: String): OSType = OSType.values().first { it.osname == osname }
	}
}

val NCALAYER_HOME = File(when (CURRENTOS) {
	OSType.MACOS -> File(USER_HOME, "Library/Application Support")
	OSType.LINUX -> File(USER_HOME, ".config")
	OSType.WINDOWS -> File(System.getenv("APPDATA"))
	else -> File(USER_HOME, ".config")
}, "NCALayer")

val MAIN_LOG = File(NCALAYER_HOME, "ncalayer.log")
val UPDATE_FILE = File(NCALAYER_HOME, UPDATE_FILENAME)
val BUNDLES_DIR = File(NCALAYER_HOME, "bundles")

object NCALayer {

	init {
		System.setProperty("ncalayer.mainlog", MAIN_LOG.path)
		if (!BUNDLES_DIR.exists()) {
			BUNDLES_DIR.mkdirs()
		}
	}

	private val LOG = loggerFor(javaClass)

	private fun getConditionalPermissionAdmin(context: BundleContext): ConditionalPermissionAdmin {
		val ref = context.getServiceReference(ConditionalPermissionAdmin::class.java.getName());
		return context.getService(ref) as ConditionalPermissionAdmin
	}

	private fun initFromScratch(ctx: BundleContext, unpack: Boolean): Boolean {
		LOG.info("Init from scratch...")
		val jarBundleList = mutableListOf<String>()
		return try {
			if (!LOCATION.isDirectory) {
				ZipFile(LOCATION).use { zf ->
					jarBundleList.addAll(zf.entries().toList().
							filter { it.name.startsWith("kncabundles/") && !it.isDirectory }.
							map { "/${it.name}" })
				}
			} else {
				jarBundleList.addAll(File(LOCATION, "kncabundles/").walk().
						filterNot { it.isDirectory && !it.endsWith(".jar") }.
						map { "/kncabundles/${it.name}" })
			}

			LOG.info("JAR-Bundles: $jarBundleList")
			if (jarBundleList.size == 0) {
				throw IllegalArgumentException("KNCA bundles not found!")
			}

			jarBundleList.forEach {
				val jarUrl = "jar:" + LOCATION.toURI() + "!" + it
				val jis = NCALayer::class.java.getResourceAsStream(it)
				if (unpack) {
					Files.copy(jis, Paths.get(File(BUNDLES_DIR, it.removePrefix("/kncabundles/")).toURI()), StandardCopyOption.REPLACE_EXISTING)
					LOG.info("$jarUrl unpacked.")
				} else {
					ctx.installBundle(jarUrl, jis)
					LOG.info("$jarUrl installed.")
				}
				jis.close()
			}
			true
		} catch (e: Exception) {
			LOG.error("First start failed!", e)
			false
		}
	}

	private fun updatePermissions(ctx: BundleContext, bjList: List<BundleJSON>) {
		val permAdmin = getConditionalPermissionAdmin(ctx);
		val permUpdate = permAdmin.newConditionalPermissionUpdate();
		val permInfos = permUpdate.getConditionalPermissionInfos();
		permInfos.clear();
		val conditionInfoArgs = mutableListOf<String>()
		for (bj in bjList) {
			conditionInfoArgs.add("${bj.symname}|${bj.csernum}|${bj.chash}")
		}
		permInfos.add(permAdmin.newConditionalPermissionInfo("Signed bundles",
				arrayOf<ConditionInfo>(ConditionInfo(CertCondition::class.java.name, conditionInfoArgs.toTypedArray())),
				arrayOf<PermissionInfo>(PermissionInfo(AllPermission::class.java.name, "*", "*")),
				ConditionalPermissionInfo.ALLOW))
		permUpdate.commit();
	}

	@JvmStatic fun main(args: Array<String>) {

		LOG.info("NCALayer $CORE_VERSION")
		val provider = KalkanProvider()
		Security.addProvider(provider)
		SysOutOverSLF4J.sendSystemOutAndErrToSLF4J();
		val policyFile = if (LOCATION.isDirectory) {
			"${LOCATION_URI}all.policy"
		} else {
			"jar:$LOCATION_URI!/all.policy"
		}

		LOG.info(System.getProperty("os.name"))
		LOG.info(NCALAYER_HOME.toString())
		LOG.info(LOCATION.toString())

		try {
			if (NCALayer::class.java.signers == null && NCALayer::class.java.getPackage().implementationVersion != null) {
				throw SecurityException("Core is unsigned!")
			}
			val coreVer = Version.parseVersion(CORE_VERSION)

			val ufexists = if (UPDATE_FILE.exists()) true else false

			val ncalayerJSON = if (UPDATE_FILE.exists()) {
				val signedJSONData = UPDATE_FILE.readBytes()
				val existJSON = retrieveJSON(signedJSONData)
				if (coreVer.compareTo(Version.parseVersion(existJSON.version)) > 0) {
					retrieveJSON(extractJSON())
				} else existJSON
			} else {
				retrieveJSON(extractJSON())
			}

			val map = mapOf<String, Any>(
					//					Constants.FRAMEWORK_STORAGE_CLEAN to Constants.FRAMEWORK_STORAGE_CLEAN_ONFIRSTINIT,
					Constants.FRAMEWORK_STORAGE to "$NCALAYER_HOME/ncalayer-cache",
					CORE_BUNDLESDIR_PROP to BUNDLES_DIR.path,
					CORE_VERSION_PROP to CORE_VERSION,
					CORE_OSNAME_PROP to OSNAME,
					CORE_LOCATION_PROP to LOCATION.path,
					Constants.FRAMEWORK_SECURITY to "osgi",
					FelixConstants.LOG_LOGGER_PROP to FelixLogger(),
					FelixConstants.LOG_LEVEL_PROP to System.getProperty("ncalayer.loglevel", "3"),
					Constants.FRAMEWORK_SYSTEMPACKAGES_EXTRA to "javafx.beans.property,javafx.beans.value,javafx.scene.control.cell,javafx.scene.image,javafx.event,javafx.util,kz.gov.pki.osgi.layer.api,org.json,kotlin,kotlin.jvm.internal,kotlin.collections,org.osgi.service.log,org.slf4j,org.slf4j.impl,javax.smartcardio,javafx.application,javafx.collections,javafx.fxml,javafx.geometry,javafx.scene,javafx.scene.control,javafx.scene.layout,javafx.scene.paint,javafx.scene.text,javafx.scene.web,javafx.stage,javafx.util,javax.xml.parsers,org.w3c.dom,org.xml.sax,javax.net.ssl,javax.swing,javax.xml.namespace,javax.xml.stream,javax.xml.stream.events,javax.crypto,sun.security.jca,javax.crypto.spec,javax.servlet")

			System.setProperty("java.security.policy", policyFile)
			Policy.getPolicy().refresh()

			val fw = FrameworkFactory().newFramework(map)
			fw.init()
			val ctx = fw.bundleContext
			SecurityActivator().start(ctx)
			Activator().start(ctx)

			updatePermissions(ctx, ncalayerJSON.bundles);

			val jsonVer = Version.parseVersion(ncalayerJSON.version)
			val vercomp = coreVer.compareTo(jsonVer)
			val unpack = if (vercomp < 0 || !ufexists) true else false

			if (ctx.bundles.size == 1 || unpack) {
				if (!initFromScratch(ctx, unpack)) {
					throw IllegalArgumentException("Couldn't init from scratch.")
				}
			}

			LOG.info("Scanning bundles directory...")
			Updater.scanBundlesDir(ctx)

			val allSymNames = ctx.bundles.map { it.symbolicName }.toSet()
			if (!allSymNames.containsAll(ncalayerJSON.listRequiredSymNames())) {
				throw IllegalArgumentException("Required core bundles not found!")
			}

			ctx.bundles.forEach {
				LOG.info("${it.symbolicName} : ${it.version}")
				it.start()
			}

			LOG.info("Downloading updates info...")
			Updater.check(ctx, ncalayerJSON)

		} catch(e: Exception) {
			LOG.error("Failed.", e)
			JOptionPane.showMessageDialog(null, "Не удалось запустить NCALayer.\nПодробности в файле логирования $MAIN_LOG.",
					"Ошибка запуска", JOptionPane.ERROR_MESSAGE);
			System.exit(0)
		}
	}

	private fun extractJSON(): ByteArray {
		Files.newOutputStream(UPDATE_FILE.toPath(), StandardOpenOption.CREATE).use { os ->
			NCALayer::class.java.getResourceAsStream("/$UPDATE_FILENAME").use {
				os.write(it.readBytes())
			}
		}
		return UPDATE_FILE.readBytes()
	}
}