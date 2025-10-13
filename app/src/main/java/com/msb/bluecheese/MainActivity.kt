package com.msb.bluecheese

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import android.widget.Toast
import android.util.Base64
import com.google.android.material.button.MaterialButton
import java.nio.charset.StandardCharsets.UTF_8
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.text.Normalizer //to ensure it works on all devices for cross device compatability

//in this version I switched to PBKDF2 + AES-GCM (AEAD) for a better encryption

class MainActivity : AppCompatActivity() {

    private lateinit var textInput: EditText
    private lateinit var passphraseInput: EditText
    private lateinit var outputText: TextView

    //AEAD params
    private val RNG = SecureRandom()
    private val KDF_ITERATIONS = 200_000            //can be tuned if too slow on a device
    //tested on Google Pixel 9a runs in few sec. also tested on Galaxy Zfold5 runs faster
    //tho some recommendation is to use 600,000 however might be too slow on some devices
    private val SALT_LEN = 16                       //128-bit salt
    private val GCM_NONCE_LEN = 12                  //96-bit nonce

     private val GCM_TAG_LEN_BITS = 128              //128-bit tag

    //envelope format: BC2:GCM:PBKDF2:<iter>:<saltB64>:<nonceB64>:<cipherB64>
    private val ENVELOPE_MAGIC = "BC2"
    private val ENVELOPE_ALG = "GCM"
    private val ENVELOPE_KDF = "PBKDF2"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        textInput = findViewById(R.id.text_input)
        passphraseInput = findViewById(R.id.passphrase_input)
        outputText = findViewById(R.id.output_text)


        val pasteButton: MaterialButton = findViewById(R.id.paste_button)

            val copyButton: MaterialButton = findViewById(R.id.copy_button)

        findViewById<MaterialButton>(R.id.clear_button).setOnClickListener { textInput.setText("") }

        findViewById<View>(R.id.encrypt_button).setOnClickListener { onEncryptClicked() }
        findViewById<View>(R.id.decrypt_button).setOnClickListener {
            onDecryptClicked()
        }

        pasteButton.setOnClickListener {
            pasteTextFromClipboard()
        }
        copyButton.setOnClickListener { copyTextToClipboard(outputText.text.toString()) }

        findViewById<View>(R.id.about_button).setOnClickListener { showAboutDialog() }

        findViewById<View>(R.id.quit_button).setOnClickListener {
            finishAffinity()
            System.exit(0)
        }
    }


    private fun onEncryptClicked() {
        try {
            val plaintext = textInput.text.toString()
            val passphrase = normalizePass(passphraseInput.text.toString())

            if (plaintext.isEmpty() || passphrase.isEmpty()) {
                showErrorDialog("Input Error", "Text and passphrase fields cannot be empty.")
                return
            }
            val encryptedText = encrypt(plaintext, passphrase)
            outputText.text = encryptedText
        } catch (e: Exception) {
            showErrorDialog("Encryption Error", "An error occurred during encryption: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun onDecryptClicked() {
        try {
            val envelope = textInput.text.toString()
            val passphrase = normalizePass(passphraseInput.text.toString())

            if (envelope.isEmpty() || passphrase.isEmpty()) {
                showErrorDialog("Input Error", "Ciphertext and passphrase fields cannot be empty.")
                return
            }
            val decryptedText = decrypt(envelope, passphrase)
            outputText.text = decryptedText
        } catch (e: Exception) {
            showErrorDialog("Decryption Error", "An error occurred during decryption: ${e.message}")
            e.printStackTrace()
        }
    }

    //about diag.
    private fun showAboutDialog() {
        val inflater = layoutInflater
        val dialogLayout = inflater.inflate(R.layout.dialog_custom, null)

        val developer = "- by msb"

        //    val info = ""

        val algoInfo = """
            Encryption: v2 - AES-256-GCM (AEAD)
            Key derivation: PBKDF2-HMAC-SHA256 - $KDF_ITERATIONS iters - 16-byte salt
            Nonce: 12-byte random - Tag: 128-bit
        """.trimIndent()

        //Format: $ENVELOPE_MAGIC:$ENVELOPE_ALG:$ENVELOPE_KDF:iter:salt:nonce:cipher

        val aboutText = dialogLayout.findViewById<TextView?>(R.id.dialog_message)
        aboutText?.text = "$developer\n\n$algoInfo"

        val builder = AlertDialog.Builder(this)
        builder.setView(dialogLayout)
        builder.setPositiveButton("Close", null)
        builder.show()
    }

    //brand new AEAD encrypt/decrypt
    private fun encrypt(plaintext: String, passphrase: String): String {
        require(passphrase.isNotEmpty()) { "Password is empty" }

        val salt = ByteArray(SALT_LEN).also { RNG.nextBytes(it) }
        val key = deriveKeyPBKDF2(passphrase, salt, KDF_ITERATIONS)

        val nonce = ByteArray(GCM_NONCE_LEN).also { RNG.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LEN_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)

        val ct = cipher.doFinal(plaintext.toByteArray(UTF_8))

        return listOf(
            ENVELOPE_MAGIC,
            ENVELOPE_ALG,
            ENVELOPE_KDF,
            KDF_ITERATIONS.toString(),
            b64(salt),
            b64(nonce),
            b64(ct)
        ).joinToString(":")
    }

    private fun decrypt(cipherEnvelope: String, passphrase: String): String {
        require(passphrase.isNotEmpty()) { "Password is empty" }

        val raw = cipherEnvelope.trim()                   //here we trim global whitespace
        val parts = raw.split(":").map { it.trim() }      //trim each field -- imp
        require(parts.size == 7 && parts[0] == ENVELOPE_MAGIC && parts[1] == ENVELOPE_ALG && parts[2] == ENVELOPE_KDF) {
            "Invalid message format"
        }

        val iterations = parts[3].toInt()
        val salt  = b64d(parts[4])                        //b64d strips whitespace + tolerant decode
        val nonce = b64d(parts[5])
        val ct    = b64d(parts[6])

        val key = deriveKeyPBKDF2(passphrase, salt, iterations)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LEN_BITS, nonce)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        return try {
            val pt = cipher.doFinal(ct)
            String(pt, UTF_8)
        } catch (e: AEADBadTagException) {
            throw Exception("Decryption failed: incorrect password or data corrupted")
        }
    }

    //key deriv.
    private fun deriveKeyPBKDF2(password: String, salt: ByteArray, iterations: Int): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256) //AES-256
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }


    private fun normalizePass(raw: String): String {

        val nfkc = Normalizer.normalize(raw, Normalizer.Form.NFKC).trim()

        return nfkc
            .replace(Regex("[\\u200B-\\u200D\\uFEFF]"), "")
            .replace("\u00A0", " ")
    }


    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun b64d(s: String): ByteArray =
        Base64.decode(s.replace(Regex("\\s+"), ""), Base64.DEFAULT)

    //clipboard
    private fun showErrorDialog(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun copyTextToClipboard(text: String) {
        if (text.isNotEmpty()) {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Copied Text", text)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "No text to copy", Toast.LENGTH_SHORT).show()
        }
    }

    private fun pasteTextFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (clipboard.hasPrimaryClip() &&
            clipboard.primaryClipDescription?.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN) == true) {
             val pasteText = clipboard.primaryClip?.getItemAt(0)?.text

            if (!pasteText.isNullOrEmpty()) {

                textInput.setText(pasteText.toString())
                Toast.makeText(this, "Pasted from clipboard", Toast.LENGTH_SHORT).show()
            }
        } else {
            Toast.makeText(this, "Nothing to paste", Toast.LENGTH_SHORT).show()
        }
    }
}
