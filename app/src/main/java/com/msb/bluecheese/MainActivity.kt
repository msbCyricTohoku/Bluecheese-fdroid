package com.msb.bluecheese

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.util.Base64
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets.UTF_8
import java.security.SecureRandom
import java.text.Normalizer
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

//some new additions and updatyes to me code

class MainActivity : AppCompatActivity() {

    private lateinit var textInput: EditText
    private lateinit var passphraseInput: EditText
    private lateinit var outputText: TextView
    private lateinit var expirySwitch: MaterialSwitch
    private lateinit var encryptButton: MaterialButton
    private lateinit var decryptButton: MaterialButton

    //AEAD params
    private val RNG = SecureRandom()
    private val KDF_ITERATIONS = 200_000            //can be tuned if too slow on a device
    private val SALT_LEN = 16                       //128-bit salt
    private val GCM_NONCE_LEN = 12                  //96-bit nonce
    private val GCM_TAG_LEN_BITS = 128              //128-bit tag

    //envelope format: BC2:GCM:PBKDF2:<iter>:<saltB64>:<nonceB64>:<cipherB64>
    private val ENVELOPE_MAGIC = "BC2"
    private val ENVELOPE_ALG = "GCM"
    private val ENVELOPE_KDF = "PBKDF2"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        setContentView(R.layout.activity_main)

        textInput = findViewById(R.id.text_input)
        passphraseInput = findViewById(R.id.passphrase_input)
        outputText = findViewById(R.id.output_text)
        expirySwitch = findViewById(R.id.expiry_switch)
        encryptButton = findViewById(R.id.encrypt_button)
        decryptButton = findViewById(R.id.decrypt_button)

        val pasteButton: MaterialButton = findViewById(R.id.paste_button)
        val copyButton: MaterialButton = findViewById(R.id.copy_button)
        val shareButton: MaterialButton = findViewById(R.id.share_button)

        findViewById<MaterialButton>(R.id.clear_button).setOnClickListener { textInput.setText("") }

        encryptButton.setOnClickListener { onEncryptClicked() }
        decryptButton.setOnClickListener { onDecryptClicked() }

        pasteButton.setOnClickListener { pasteTextFromClipboard() }
        copyButton.setOnClickListener { copyTextToClipboard(outputText.text.toString()) }
        shareButton.setOnClickListener { shareOutputText() }

        findViewById<View>(R.id.about_button).setOnClickListener { showAboutDialog() }
          findViewById<View>(R.id.quit_button).setOnClickListener {
         finishAffinity()
        }

        handleIncomingIntents(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleIncomingIntents(intent)
    }

    private fun handleIncomingIntents(intent: Intent?) {
        val action = intent?.action
        val type = intent?.type

        if (Intent.ACTION_SEND == action && "text/plain" == type) {
            intent.getStringExtra(Intent.EXTRA_TEXT)?.let { textInput.setText(it) }
        } else if (Intent.ACTION_PROCESS_TEXT == action && "text/plain" == type) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.let { textInput.setText(it.toString()) }
            }
        }
    }

    private fun onEncryptClicked() {
        val plaintext = textInput.text.toString()
        val passphrase = normalizePass(passphraseInput.text.toString())
        val isTimeBomb = expirySwitch.isChecked

        if (plaintext.isEmpty() || passphrase.isEmpty()) {
            showErrorDialog("Input Error", "Text and passphrase fields cannot be empty.")
            return
        }

        setLoadingState(true, "Ciphering...")

        lifecycleScope.launch {
            try {
                val encryptedText = withContext(Dispatchers.Default) {
                    encrypt(plaintext, passphrase, isTimeBomb)
                }
                outputText.text = encryptedText
            } catch (e: Exception) {
                showErrorDialog("Encryption Error", "An error occurred during encryption: ${e.message}")
                e.printStackTrace()
            } finally {
                setLoadingState(false, "Cipher")
            }
        }
    }

    private fun onDecryptClicked() {
        val envelope = textInput.text.toString()
        val passphrase = normalizePass(passphraseInput.text.toString())

        if (envelope.isEmpty() || passphrase.isEmpty()) {
            showErrorDialog("Input Error", "Ciphertext and passphrase fields cannot be empty.")
            return
        }

        setLoadingState(true, "Deciphering...")

        lifecycleScope.launch {
            try {
                val decryptedText = withContext(Dispatchers.Default) {
                    decrypt(envelope, passphrase)
                }
                outputText.text = decryptedText
                expirySwitch.isChecked = false
            } catch (e: Exception) {
                showErrorDialog("Decryption Error", e.message ?: "Incorrect password or corrupted data.")
                e.printStackTrace()
            } finally {
                setLoadingState(false, "Decipher")
            }
        }
    }

    private fun setLoadingState(isLoading: Boolean, defaultEncryptText: String) {
        encryptButton.isEnabled = !isLoading
        decryptButton.isEnabled = !isLoading
        if (isLoading) {
            encryptButton.text = defaultEncryptText
            decryptButton.text = "Wait..."
        } else {
            encryptButton.text = "Cipher"
            decryptButton.text = "Decipher"
        }
    }

    private fun showAboutDialog() {
        val inflater = layoutInflater
        val dialogLayout = inflater.inflate(R.layout.dialog_custom, null)
        val developer = "- by msb"

        val algoInfo = """
            Encryption: v3 - AES-256-GCM (AEAD)
            Key derivation: PBKDF2-HMAC-SHA256 - $KDF_ITERATIONS iters
            Features: Anti-Screenshot, Time-Bomb, Async Crypto, System Integration
        """.trimIndent()

        val aboutText = dialogLayout.findViewById<TextView?>(R.id.dialog_message)
        aboutText?.text = "$developer\n\n$algoInfo"

        AlertDialog.Builder(this)
            .setView(dialogLayout)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun encrypt(plaintext: String, passphrase: String, isTimeBomb: Boolean): String {
        require(passphrase.isNotEmpty()) { "Password is empty" }

        val finalPlaintext = if (isTimeBomb) {
            val expiryMs = System.currentTimeMillis() + (60 * 60 * 1000L) // +1 Hour
            "BC_EXP:$expiryMs|$plaintext"
        } else {
            plaintext
        }

        val salt = ByteArray(SALT_LEN).also { RNG.nextBytes(it) }
        val key = deriveKeyPBKDF2(passphrase, salt, KDF_ITERATIONS)

        val nonce = ByteArray(GCM_NONCE_LEN).also { RNG.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LEN_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)

        val ct = cipher.doFinal(finalPlaintext.toByteArray(UTF_8))

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

        val raw = cipherEnvelope.trim()
        val parts = raw.split(":").map { it.trim() }
        require(parts.size == 7 && parts[0] == ENVELOPE_MAGIC && parts[1] == ENVELOPE_ALG && parts[2] == ENVELOPE_KDF) {
            "Invalid message format"
        }

        val iterations = parts[3].toInt()
        val salt  = b64d(parts[4])
        val nonce = b64d(parts[5])
        val ct    = b64d(parts[6])

        val key = deriveKeyPBKDF2(passphrase, salt, iterations)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LEN_BITS, nonce)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        return try {
            val pt = cipher.doFinal(ct)
            val decryptedStr = String(pt, UTF_8)

            // FEATURE 4: Verify time-bomb expiry
            if (decryptedStr.startsWith("BC_EXP:")) {
                val pipeIdx = decryptedStr.indexOf('|')
                if (pipeIdx != -1) {
                    val expStr = decryptedStr.substring(7, pipeIdx)
                    val expiry = expStr.toLongOrNull() ?: 0L
                    if (System.currentTimeMillis() > expiry) {
                        return "🚨 THIS MESSAGE EXPIRED AND HAS SELF-DESTRUCTED."
                    }
                    return decryptedStr.substring(pipeIdx + 1)
                }
            }
            decryptedStr
        } catch (e: AEADBadTagException) {
            throw Exception("Decryption failed: incorrect password or data corrupted")
        }
    }

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

    private fun showErrorDialog(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("Close", null)
            .show()
    }

    // Instantly sends the output directly to another app via Android Share menu
    private fun shareOutputText() {
        val text = outputText.text.toString()
        if (text.isBlank() || text.contains("appear here") || text.contains("SELF-DESTRUCTED")) {
            Toast.makeText(this, "Nothing to share", Toast.LENGTH_SHORT).show()
            return
        }
        val sendIntent = Intent().apply {
            action = Intent.ACTION_SEND
            putExtra(Intent.EXTRA_TEXT, text)
            type = "text/plain"
        }
        startActivity(Intent.createChooser(sendIntent, "Send secure message via..."))
    }
    private fun copyTextToClipboard(text: String) {
        if (text.isNotEmpty() && !text.contains("appear here") && !text.contains("SELF-DESTRUCTED")) {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Copied Text", text)

            // Tell Android 13+ keyboards NOT to save this in clipboard history
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                clip.description.extras = PersistableBundle().apply {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }

            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Copied! Auto-clearing in 45s...", Toast.LENGTH_SHORT).show()

            // Time-delayed self-clearing of clipboard
            lifecycleScope.launch {
                delay(45_000) // 45 seconds
                if (clipboard.primaryClip?.getItemAt(0)?.text == text) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        clipboard.clearPrimaryClip()
                    } else {
                        clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                    }
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Clipboard cleared for safety", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        } else {
            Toast.makeText(this, "No valid text to copy", Toast.LENGTH_SHORT).show()
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