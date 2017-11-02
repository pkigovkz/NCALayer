package kz.gov.pki.osgi.layer.core

import kotlin.concurrent.thread
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.SSLContext
import java.security.SecureRandom
import java.io.File
import java.util.jar.JarFile
import org.osgi.framework.Constants
import kz.gov.pki.osgi.layer.api.NCALayerService
import org.osgi.util.tracker.ServiceTracker
import org.osgi.framework.BundleContext
import org.osgi.framework.Version
import org.slf4j.LoggerFactory
import java.net.HttpURLConnection
import kz.gov.pki.osgi.layer.api.NCALayerJSON
import java.security.Security
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import java.net.ConnectException
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.lang.management.ManagementFactory
import java.lang.Exception
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.io.ByteArrayInputStream
import kz.gov.pki.kalkan.util.encoders.Hex
import javax.swing.JOptionPane
import org.apache.commons.compress.archivers.zip.ZipFile
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.PosixFilePermission

object Updater {
	fun scanBundlesDir(ctx: BundleContext) {
		BUNDLES_DIR.walk().filter { !it.isDirectory && it.name.endsWith(".jar") }.forEach {
			val mlocation = it.toURI().toString()
			LOG.info("JAR: {}", mlocation)
			JarFile(it, true).use { jf ->
				val mainAttrs = jf.manifest?.mainAttributes
				val bundleVersion = Version.parseVersion(mainAttrs?.getValue(Constants.BUNDLE_VERSION))
				val bundleSymName = mainAttrs?.getValue(Constants.BUNDLE_SYMBOLICNAME)

				if (bundleSymName != null) {
					try {
						val cBundle = ctx.bundles.asSequence().filter { bundleSymName.equals(it.symbolicName) }.firstOrNull()
						if (cBundle == null) {
							ctx.installBundle(mlocation)
							LOG.info("$bundleSymName : $bundleVersion successfully installed")
						} else {
							val verRes = cBundle.version.compareTo(bundleVersion)
							when {
								verRes < 0 -> {
									ctx.installBundle(mlocation)
									LOG.info("$bundleSymName : $bundleVersion successfully installed")
									cBundle.uninstall()
									LOG.info("${cBundle.symbolicName} : ${cBundle.version} successfully uninstalled")
								}
								verRes == 0 -> {
									LOG.info("$bundleSymName : $bundleVersion is already installed")
								}
								verRes > 0 -> {
									LOG.info("The newer version $bundleSymName : $bundleVersion is already installed")
								}
							}
						}
					} catch(vc: Exception) {
						LOG.error("Couldnt install the bundle!", vc)
					}
				} else {
					LOG.error("No symbolicName or version!")
				}
			}
			it.delete()
		}
	}

	fun check(ctx: BundleContext, defaultJSON: NCALayerJSON) {
		thread() {
//			System.setProperty("http.nonProxyHosts", "localhost|10.250.1.12|devsrv")
			val ncalayerJSON = try {
				LOG.info("Connecting... ${defaultJSON.updurl}")
				val updurl = URL(defaultJSON.updurl)
				val con = if ("https".equals(updurl.protocol)) {
					val scon = updurl.openConnection() as HttpsURLConnection
					scon.sslSocketFactory = createSSLContext().socketFactory
					scon
				} else {
					updurl.openConnection() as HttpURLConnection
				}
				con.connectTimeout = 5000;
				con.readTimeout = 10000;
				if (con.responseCode == HttpURLConnection.HTTP_OK) {
					val inStream = con.getInputStream()
					val data = inStream.use { it.readBytes() }
					val ret = retrieveJSON(data)
					Files.write(UPDATE_FILE.toPath(), data, StandardOpenOption.CREATE)
					ret
				} else {
					throw ConnectException("${con.responseCode} ${con.responseMessage}")
				}
			} catch(e: Exception) {
				LOG.error("Something went wrong. Referring to local JSON...", e)
				defaultJSON
			}
			val curVer = Version.parseVersion(CORE_VERSION)
			val jsonVer = Version.parseVersion(ncalayerJSON.version)
			val verRes = curVer.compareTo(jsonVer)
			LOG.info("$curVer vs $jsonVer")
			if (verRes < 0) {
				try {
					val distUrl = when (CURRENTOS) {
						OSType.MACOS -> ncalayerJSON.disturls.filter { it.type.equals("appzip") }.first()
						OSType.LINUX -> ncalayerJSON.disturls.filter { it.type.equals("setupsh") }.first()
						OSType.WINDOWS -> ncalayerJSON.disturls.filter { it.type.equals("setupexe") }.first()
						else -> ncalayerJSON.disturls.filter { it.type.equals("jar") }.first()
					}
					val url = distUrl.url
					LOG.info("Downloading new version... $url")
					val jcon = URL(url).openConnection() as HttpURLConnection
					val downloadedFile = File(NCALAYER_HOME, url.substringAfterLast('/'))
					jcon.inputStream.use {
						val bytes = it.readBytes()
						val hash = MessageDigest.getInstance("SHA-256", "SUN").digest(bytes)
						val bais = ByteArrayInputStream(bytes)
						LOG.info(Hex.encodeStr(hash))
						if (!distUrl.hash.equals(Hex.encodeStr(hash))) {
							throw Exception("Wrong hash for NCALayer!")
						}
						Files.copy(bais, downloadedFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
					}
					JOptionPane.showMessageDialog(null, "Загружено обновление. NCALayer будет перезапущен автоматически!\n" +
							ncalayerJSON.info,
							"Обновление", JOptionPane.WARNING_MESSAGE);
					restartApplication(downloadedFile.toString())
				} catch(e: Exception) {
					LOG.error("Could not update NCALayer!", e)
					JOptionPane.showMessageDialog(null, "Не удалось провести обновление для NCALayer.\n" +
							"Если ошибка будет повторяться - просим обратиться в службу поддержки.\n" +
							"Подробности в файле логирования $MAIN_LOG.\n" +
							ncalayerJSON.info,
							"Ошибка обновления", JOptionPane.ERROR_MESSAGE);
				}
			} else {
				val serviceTracker = ServiceTracker<NCALayerService, NCALayerService>(ctx, NCALayerService::class.java.name, null)
				serviceTracker.open()
				val layerService = serviceTracker.getService()
				layerService.setUpdateFile(ncalayerJSON)
			}
		}
	}

	private fun createSSLContext() : SSLContext {
		val ks = KeyStore.getInstance("JKS")
		ks.load(NCALayer::class.java.getResourceAsStream("/trusted.jks"), null)
		val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
		tmf.init(ks)
		val sslCtx = SSLContext.getInstance("TLS")
		sslCtx.init(null, tmf.trustManagers, SecureRandom());
		return sslCtx
	}

	private fun restartApplication(downloadedFile: String) {
		try {
			Runtime.getRuntime().addShutdownHook(thread(false) {
				try {
					UPDATE_FILE.delete()
					when (CURRENTOS) {
						OSType.WINDOWS -> {
							LOG.info("$downloadedFile will be executed!")
							ProcessBuilder(downloadedFile).start()
						}
						OSType.MACOS -> restartOnMac(downloadedFile)
						OSType.LINUX -> {
							File(downloadedFile).copyTo(LOCATION, true)
							LOCATION.setExecutable(true)
							val pb = ProcessBuilder(LOCATION.path, "--run")
							LOG.info("${pb.command()} will be executed!")
							pb.start()
						}
						else -> JOptionPane.showMessageDialog(null, "Ваша версия NCALayer не поддерживает автообновление.\n" +
								"Скачайте последнюю версию для вашей операционной системы на сайте НУЦ РК.",
								"Ошибка обновления", JOptionPane.ERROR_MESSAGE);
					}
				} catch (e: Exception) {
					LOG.error("Executing error!", e)
					e.printStackTrace()
				}
			})
		} catch (e: Exception) {
			LOG.error("Error while trying to restart the application", e)
		}
		System.exit(0)
	}

	private fun getFilePermissions(umode: CharArray): Set<PosixFilePermission> {
		val sb = StringBuilder()
		for (perm in umode) {
			val num = perm.toInt()
			sb.append(if ((num and 4) == 0) '-' else 'r')
			sb.append(if ((num and 2) == 0) '-' else 'w')
			sb.append(if ((num and 1) == 0) '-' else 'x')
		}
		return PosixFilePermissions.fromString(sb.toString())
	}

	private fun restartOnMac(downloadedFile: String) {
		val app = File(LOCATION.path.substringBefore(".app/Contents/Java/") + ".app")
		val appDir = app.parentFile
		if (app.exists()) app.deleteRecursively()
		ZipFile(downloadedFile).use { zf ->
			val entries = zf.entries.asSequence()
			for (entry in entries) {
				val umode = Integer.toOctalString(entry.unixMode)
				val umode2 = umode.substring(umode.length - 3, umode.length)
				val filePerms = getFilePermissions(umode2.toCharArray())
				val nf = File(appDir, entry.name)
				if (entry.isDirectory) {
					nf.mkdir()
				} else {
					zf.getInputStream(entry).use {
						Files.copy(it, nf.toPath(), StandardCopyOption.REPLACE_EXISTING)
					}
				}
				Files.setPosixFilePermissions(nf.toPath(), filePerms)
			}
		}
		val launcher = "$app/Contents/MacOS/NCALayer"
		LOG.info("$launcher will be executed!")
		ProcessBuilder(launcher).start()
	}

	private val LOG = loggerFor(Updater::class.java)
	private val SUN_JAVA_COMMAND = "sun.java.command"
}