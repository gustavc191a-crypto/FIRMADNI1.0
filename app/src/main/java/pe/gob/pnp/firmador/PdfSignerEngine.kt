package pe.gob.pnp.firmador

import com.tom_roush.pdfbox.pdmodel.PDDocument
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.SignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Calendar

class PdfSignerEngine(
    private val dnieCard: DnieSmartCard,
    private val certificate: X509Certificate
) : SignatureInterface {

    fun signPdf(sourcePdf: InputStream, targetPdf: OutputStream) {
        val document = PDDocument.load(sourcePdf)
        val signature = PDSignature().apply {
            setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            name = certificate.subjectX500Principal.name
            signDate = Calendar.getInstance()
            reason = "Firma Digital DNIe"
        }

        val options = SignatureOptions().apply {
            preferredSignatureSize = 0x8000
        }

        document.addSignature(signature, this, options)
        document.saveIncremental(targetPdf)
        document.close()
    }

    override fun sign(content: InputStream): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        var n: Int
        val contentBytesOut = ByteArrayOutputStream()
        while (content.read(buffer).also { n = it } != -1) {
            contentBytesOut.write(buffer, 0, n)
            md.update(buffer, 0, n)
        }
        val documentDigest = md.digest()

        val rawRsaSignature = dnieCard.signSha256Digest(documentDigest)

        val certList = listOf(certificate)
        val certs = JcaCertStore(certList)

        val gen = CMSSignedDataGenerator()
        val signer = object : ContentSigner {
            private val stream = ByteArrayOutputStream()
            override fun getAlgorithmIdentifier() = org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.sha256WithRSAEncryption
            )
            override fun getOutputStream(): OutputStream = stream
            override fun getSignature(): ByteArray = rawRsaSignature
        }

        val signerInfoGen = SignerInfoGeneratorBuilder(
            org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build()
        ).build(signer, org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(certificate))

        gen.addSignerInfoGenerator(signerInfoGen)
        gen.addCertificates(certs)

        val msg: CMSTypedData = CMSProcessableByteArray(contentBytesOut.toByteArray())
        val signedData = gen.generate(msg, false)

        return signedData.encoded
    }
}
