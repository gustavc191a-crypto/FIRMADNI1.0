package pe.gob.pnp.firmador

import android.nfc.tech.IsoDep
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class DnieSmartCard(private val isoDep: IsoDep) {

    companion object {
        private val AID_PKI = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            0x08.toByte(), 0xA0.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x00.toByte(), 0x18.toByte(), 0x40.toByte(), 0x00.toByte(), 0x01.toByte()
        )
        private val SELECT_EF_CERT_SIGN = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x02.toByte(), 0xC0.toByte(), 0x01.toByte()
        )
    }

    fun connect() {
        if (!isoDep.isConnected) {
            isoDep.connect()
            isoDep.timeout = 8000
        }
    }

    fun close() {
        if (isoDep.isConnected) {
            isoDep.close()
        }
    }

    fun selectApplet(): Boolean {
        val res = isoDep.transceive(AID_PKI)
        return checkStatus(res)
    }

    fun readSigningCertificate(): X509Certificate {
        val selectRes = isoDep.transceive(SELECT_EF_CERT_SIGN)
        if (!checkStatus(selectRes)) {
            throw Exception("No se pudo seleccionar el contenedor del certificado de firma.")
        }

        val certBytesOut = ByteArrayOutputStream()
        var offset = 0

        while (true) {
            val p1 = (offset shr 8).toByte()
            val p2 = (offset and 0xFF).toByte()
            val readCommand = byteArrayOf(0x00.toByte(), 0xB0.toByte(), p1, p2, 0x00.toByte())
            val response = isoDep.transceive(readCommand)

            if (response.size < 2) break
            val sw1 = response[response.size - 2].toInt() and 0xFF
            val sw2 = response[response.size - 1].toInt() and 0xFF

            val chunkLength = response.size - 2
            if (chunkLength > 0) {
                certBytesOut.write(response, 0, chunkLength)
            }

            if (sw1 != 0x90 || sw2 != 0x00 || chunkLength < 256) {
                break
            }
            offset += chunkLength
        }

        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(certBytesOut.toByteArray())) as X509Certificate
    }

    fun verifyPin(pin: String): Boolean {
        val pinBytes = pin.toByteArray(Charsets.US_ASCII)
        val apdu = ByteArrayOutputStream()
        apdu.write(byteArrayOf(0x00.toByte(), 0x20.toByte(), 0x00.toByte(), 0x81.toByte()))
        apdu.write(pinBytes.size)
        apdu.write(pinBytes)

        val response = isoDep.transceive(apdu.toByteArray())
        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF

        if (sw1 == 0x90 && sw2 == 0x00) return true
        if (sw1 == 0x63) {
            val remaining = sw2 and 0x0F
            throw Exception("PIN incorrecto. Intentos restantes antes de bloqueo: $remaining")
        }
        throw Exception("Error de validación del PIN. Código de estado: ${Integer.toHexString(sw1)} ${Integer.toHexString(sw2)}")
    }

    fun signSha256Digest(digest: ByteArray): ByteArray {
        val mseSet = byteArrayOf(
            0x00.toByte(), 0x22.toByte(), 0x41.toByte(), 0xB6.toByte(),
            0x06.toByte(), 0x84.toByte(), 0x01.toByte(), 0x02.toByte(), 0x80.toByte(), 0x01.toByte(), 0x02.toByte()
        )
        val mseRes = isoDep.transceive(mseSet)
        if (!checkStatus(mseRes)) {
            throw Exception("Fallo al inicializar el entorno criptográfico del DNIe.")
        }

        val digestInfoPrefix = byteArrayOf(
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(),
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
        )
        val digestInfo = ByteArrayOutputStream()
        digestInfo.write(digestInfoPrefix)
        digestInfo.write(digest)

        val psoCommand = ByteArrayOutputStream()
        psoCommand.write(byteArrayOf(0x00.toByte(), 0x2A.toByte(), 0x9E.toByte(), 0x9A.toByte()))
        psoCommand.write(digestInfo.size())
        psoCommand.write(digestInfo.toByteArray())
        psoCommand.write(0x00)

        val response = isoDep.transceive(psoCommand.toByteArray())
        if (!checkStatus(response)) {
            throw Exception("El chip rechazó la operación de cálculo de firma.")
        }

        val signature = ByteArray(response.size - 2)
        System.arraycopy(response, 0, signature, 0, signature.size)
        return signature
    }

    private fun checkStatus(res: ByteArray): Boolean {
        if (res.size < 2) return false
        val sw1 = res[res.size - 2].toInt() and 0xFF
        val sw2 = res[res.size - 1].toInt() and 0xFF
        return sw1 == 0x90 && sw2 == 0x00
    }
}
