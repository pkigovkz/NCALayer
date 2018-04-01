package kz.gov.pki.osgi.layer.core

import org.osgi.framework.Bundle
import org.osgi.service.condpermadmin.Condition
import org.osgi.service.condpermadmin.ConditionInfo
import kz.gov.pki.kalkan.util.encoders.Hex
import java.security.MessageDigest
import kotlin.jvm.JvmStatic

class CertCondition {
	companion object {
		private val LOG = loggerFor(CertCondition::class.java)
		private val CONDITION_TYPE = CertCondition::class.java.name
		@JvmStatic fun getCondition(bundle: Bundle, info: ConditionInfo): Condition {
			if (!CONDITION_TYPE.equals(info.type))
				throw IllegalArgumentException("ConditionInfo must be of type $CONDITION_TYPE")
			val signers = bundle.getSignerCertificates(Bundle.SIGNERS_ALL)
			val match = try {
				var lmatch = false
				val signer = signers.asIterable().single().key
				val csernum = Hex.encodeStr(signer.serialNumber.toByteArray())
				val md = MessageDigest.getInstance("SHA-256", "SUN")
				val chash = Hex.encodeStr(md.digest(signer.encoded))
				val matchStr = "${bundle.symbolicName}|$csernum|$chash"
				for (arg in info.args) {
					if (arg.equals(matchStr)) {
						lmatch = true
						break
					}
				}
				lmatch
			} catch (e: Exception) {
				LOG.error("Could not get condition for ${bundle.symbolicName}", e)
				false
			}
			LOG.info("Condition for ${bundle.symbolicName} is $match")
			return if (match) {
				Condition.TRUE
			} else {
				try {
					bundle.uninstall()	
				} catch (e: Exception) {
					LOG.error("Could not uninstall ${bundle.symbolicName}", e)
				}
				Condition.FALSE
			}
		}
	}
}