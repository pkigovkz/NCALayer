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
import java.net.HttpURLConnection
import kz.gov.pki.osgi.layer.api.NCALayerJSON
import java.net.ConnectException
import java.nio.file.Files
import java.lang.Exception
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.io.ByteArrayInputStream
import kz.gov.pki.kalkan.util.encoders.Hex
import javax.swing.JOptionPane
import org.apache.commons.compress.archivers.zip.ZipFile
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.PosixFilePermission
import org.osgi.framework.Bundle

object Updater {
	fun scanBundlesDir(ctx: BundleContext, json: NCALayerJSON) {
		BUNDLES_DIR.walk().filter { !it.isDirectory && it.name.endsWith(".jar") }.forEach {
			val mlocation = it.toURI().toString()
			LOG.info("JAR: {}", mlocation)
			JarFile(it, true).use { jf ->
				val mainAttrs = jf.manifest?.mainAttributes
				val bundleVersion = Version.parseVersion(mainAttrs?.getValue(Constants.BUNDLE_VERSION))
				val bundleSymName = mainAttrs?.getValue(Constants.BUNDLE_SYMBOLICNAME)
				val jsonBundle = json.bundles.find { it.symname == bundleSymName }

				if (bundleSymName != null && jsonBundle != null) {
					try {
						val cBundle = ctx.bundles.asSequence().filter { bundleSymName == it.symbolicName }.firstOrNull()
						if (cBundle == null) {
							ctx.installBundle(mlocation)
							LOG.info("($bundleSymName $bundleVersion) successfully installed")
						} else {
							val verRes = cBundle.version.compareTo(bundleVersion)
							when {
								verRes < 0 -> {
									ctx.installBundle(mlocation)
									LOG.info("($bundleSymName $bundleVersion) successfully installed")
									cBundle.uninstall()
									LOG.info("(${cBundle.symbolicName} ${cBundle.version}) successfully uninstalled")
								}
								verRes == 0 -> {
									val bundleSigner = cBundle.getSignerCertificates(Bundle.SIGNERS_ALL).keys.first()
									if (jsonBundle.csernum == Hex.encodeStr(bundleSigner.serialNumber.toByteArray())) {
										LOG.info("($bundleSymName $bundleVersion) is already installed")	
									} else {
										LOG.info("Different code-signing certificate found!")
										cBundle.uninstall()
										LOG.info("(${cBundle.symbolicName} ${cBundle.version}) successfully uninstalled")
										ctx.installBundle(mlocation)
										LOG.info("($bundleSymName $bundleVersion) successfully installed")
									}
								}
								verRes > 0 -> {
									LOG.info("The newer version ($bundleSymName $bundleVersion) is already installed")
								}
							}
						}
					} catch(vc: Exception) {
						LOG.error("Couldnt install the bundle!", vc)
					}
				} else {
					LOG.error("No symbolicName or unpermitted bundle!")
				}
			}
			it.delete()
		}
	}

	fun check(ctx: BundleContext, defaultJSON: NCALayerJSON) {
		thread {
			val ncalayerJSON = try {
				LOG.info("Connecting... ${defaultJSON.updurl}")
				val updurl = URL(defaultJSON.updurl)
				val con = if ("https" == updurl.protocol) {
					val scon = updurl.openConnection() as HttpsURLConnection
					scon.sslSocketFactory = createSSLContext().socketFactory
					scon
				} else {
					updurl.openConnection() as HttpURLConnection
				}
				con.connectTimeout = 5000
				con.readTimeout = 10000
				if (con.responseCode == HttpURLConnection.HTTP_OK) {
					val inStream = con.inputStream
					val data = inStream.use { it.readBytes() }
					val ret = retrieveJSON(data)
					Files.write(UPDATE_FILE.toPath(), data)
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
						OSType.MACOS -> ncalayerJSON.disturls.first { it.type == "appzip" }
						OSType.LINUX -> ncalayerJSON.disturls.first { it.type == "setupsh" }
						OSType.WINDOWS -> ncalayerJSON.disturls.first { it.type == "setupexe" }
						else -> ncalayerJSON.disturls.first { it.type == "jar" }
					}
					val urlStr = distUrl.url
					LOG.info("Downloading new version... $urlStr")
					val url = URL(urlStr)
					val jcon = if ("https" == url.protocol) {
						val scon = url.openConnection() as HttpsURLConnection
						scon.sslSocketFactory = createSSLContext().socketFactory
						scon
					} else {
						url.openConnection() as HttpURLConnection
					}
					jcon.connectTimeout = 5000
					jcon.readTimeout = 10000
					if (jcon.responseCode == HttpURLConnection.HTTP_OK) {
						val downloadedFile = File(NCALAYER_HOME, urlStr.substringAfterLast('/'))
						jcon.inputStream.use {
							val bytes = it.readBytes()
							val hash = MessageDigest.getInstance("SHA-256", "SUN").digest(bytes)
							val bais = ByteArrayInputStream(bytes)
							LOG.info(Hex.encodeStr(hash))
							if (distUrl.hash != Hex.encodeStr(hash)) {
								throw Exception("Wrong hash for NCALayer!")
							}
							Files.copy(bais, downloadedFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
						}
						JOptionPane.showMessageDialog(null, "Загружена новая версия ${jsonVer}. NCALayer будет перезапущен автоматически!\n" +
								"Описание обновления\n" + ncalayerJSON.info,
								"Обновление", JOptionPane.WARNING_MESSAGE)
						restartApplication(downloadedFile.toString())
					} else {
						throw ConnectException("${jcon.responseCode} ${jcon.responseMessage}")
					}
				} catch(e: Exception) {
					LOG.error("Could not update NCALayer!", e)
					JOptionPane.showMessageDialog(null, "Не удалось провести обновление для NCALayer.\n" +
							"Если ошибка будет повторяться, попробуйте скачать и переустановить NCALayer полностью.\n" +
							"Подробности в файле логирования $MAIN_LOG.\n" +
							"Описание обновления\n" + ncalayerJSON.info,
							"Ошибка обновления", JOptionPane.ERROR_MESSAGE)
				}
			} else {
				val serviceTracker = ServiceTracker<NCALayerService, NCALayerService>(ctx, NCALayerService::class.java.name, null)
				serviceTracker.open()
				val layerService = serviceTracker.service
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
		sslCtx.init(null, tmf.trustManagers, SecureRandom())
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
							File(downloadedFile).delete()
							val pb = ProcessBuilder(LOCATION.path, "--run")
							LOG.info("${pb.command()} will be executed!")
							pb.start()
						}
						else -> JOptionPane.showMessageDialog(null, "Ваша версия NCALayer не поддерживает автообновление.\n" +
								"Скачайте последнюю версию для вашей операционной системы на сайте НУЦ РК.",
								"Ошибка обновления", JOptionPane.ERROR_MESSAGE)
					}
				} catch (e: Exception) {
					LOG.error("Executing error!", e)
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
		File(downloadedFile).delete()
		val launcher = "$app/Contents/MacOS/NCALayer"
		LOG.info("$launcher will be executed!")
		ProcessBuilder(launcher).start()
	}

	private val LOG = loggerFor(Updater::class.java)
}