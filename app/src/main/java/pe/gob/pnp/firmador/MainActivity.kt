package pe.gob.pnp.firmador

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var nfcAdapter: NfcAdapter? = null
    private var selectedPdfUri: Uri? = null

    private lateinit var tvStatus: TextView
    private lateinit var tvSelectedFile: TextView
    private lateinit var etPin: EditText
    private lateinit var progressBar: ProgressBar

    private val selectPdfLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            selectedPdfUri = result.data?.data
            tvSelectedFile.text = "PDF cargado: ${selectedPdfUri?.path}"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        PDFBoxResourceLoader.init(applicationContext)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

        tvStatus = findViewById(R.id.tvStatus)
        tvSelectedFile = findViewById(R.id.tvSelectedFile)
        etPin = findViewById(R.id.etPin)
        progressBar = findViewById(R.id.progressBar)

        findViewById<Button>(R.id.btnSelectPdf).setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/pdf"
            }
            selectPdfLauncher.launch(intent)
        }
    }

    override fun onResume() {
        super.onResume()
        val options = Bundle()
        options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 500)
        nfcAdapter?.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            options
        )
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag?) {
        val isoDep = IsoDep.get(tag) ?: return
        val pin = etPin.text.toString().trim()

        if (selectedPdfUri == null) {
            runOnUiThread { Toast.makeText(this, "Primero selecciona un PDF.", Toast.LENGTH_SHORT).show() }
            return
        }

        if (pin.length < 4) {
            runOnUiThread { Toast.makeText(this, "Ingresa un PIN válido.", Toast.LENGTH_SHORT).show() }
            return
        }

        runOnUiThread {
            progressBar.visibility = View.VISIBLE
            tvStatus.text = "Mantén el DNI pegado al teléfono..."
        }

        thread {
            val dnie = DnieSmartCard(isoDep)
            try {
                dnie.connect()
                if (!dnie.selectApplet()) {
                    throw Exception("No se reconoció el chip del DNI electrónico.")
                }

                dnie.verifyPin(pin)
                val cert = dnie.readSigningCertificate()

                val inStream: InputStream? = contentResolver.openInputStream(selectedPdfUri!!)
                val signedFile = File(getExternalFilesDir(null), "Documento_Firmado_${System.currentTimeMillis()}.pdf")
                val outStream = FileOutputStream(signedFile)

                if (inStream != null) {
                    val signerEngine = PdfSignerEngine(dnie, cert)
                    signerEngine.signPdf(inStream, outStream)
                    inStream.close()
                    outStream.close()

                    runOnUiThread {
                        progressBar.visibility = View.GONE
                        tvStatus.text = "¡Firmado con éxito!\nGuardado en: ${signedFile.name}"
                        Toast.makeText(this, "Documento firmado correctamente", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    progressBar.visibility = View.GONE
                    tvStatus.text = "Error: ${e.message}"
                }
            } finally {
                dnie.close()
            }
        }
    }
}
