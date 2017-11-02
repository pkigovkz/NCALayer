package kz.gov.pki.osgi.layer.core

import org.osgi.framework.Bundle
import org.osgi.framework.ServiceReference

class FelixLogger : org.apache.felix.framework.Logger() {

	protected override fun doLog(bundle: Bundle?, sr: ServiceReference<*>?, level: Int, msg: String?, throwable: Throwable?) {
		when (level) {
			LOG_DEBUG -> {
				LOG.debug(
						"[{}]: {}: ",
						bundle?.symbolicName,
						msg,
						throwable)
			}
			LOG_ERROR -> {
				LOG.error(
						"[{}]: {}: ",
						bundle?.symbolicName,
						msg,
						throwable)
			}
			LOG_INFO -> {
				LOG.info("[{}]: {}: ", bundle?.symbolicName, msg, throwable)
			}
			LOG_WARNING -> {
				LOG.warn("[{}]: {}: ", bundle?.symbolicName, msg, throwable)
			}
		}
	}

	protected override fun doLog(level: Int, msg: String?, throwable: Throwable?) {
		when (level) {
			LOG_DEBUG -> {
				LOG.debug("{}: ", msg, throwable)
			}
			LOG_ERROR -> {
				LOG.error("{}: ", msg, throwable)
			}
			LOG_INFO -> {
				LOG.info("{}: ", msg, throwable)
			}
			LOG_WARNING -> {
				LOG.warn("{}: ", msg, throwable)
			}
		}
	}

	companion object {
		private val LOG = loggerFor(FelixLogger::class.java)
	}
}