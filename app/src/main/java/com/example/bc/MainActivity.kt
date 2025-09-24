package com.example.bc

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
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import java.nio.charset.StandardCharsets
import com.google.android.material.button.MaterialButton

class MainActivity : AppCompatActivity() {

    private lateinit var textInput: EditText
    private lateinit var passphraseInput: EditText
    private lateinit var outputText: TextView
    //private lateinit var pasteButton: ImageButton
    //private lateinit var copyButton: ImageButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)



        textInput = findViewById(R.id.text_input)
        passphraseInput = findViewById(R.id.passphrase_input)
        outputText = findViewById(R.id.output_text)
        //pasteButton = findViewById(R.id.paste_button)
        //copyButton = findViewById(R.id.copy_button)


        val pasteButton: MaterialButton = findViewById(R.id.paste_button)
        val copyButton: MaterialButton = findViewById(R.id.copy_button)


        findViewById<View>(R.id.encrypt_button).setOnClickListener {
            onEncryptClicked()
        }

        findViewById<View>(R.id.decrypt_button).setOnClickListener {
            onDecryptClicked()
        }

        pasteButton.setOnClickListener {
            pasteTextFromClipboard()
        }

        copyButton.setOnClickListener {
            copyTextToClipboard(outputText.text.toString())
        }

        findViewById<View>(R.id.about_button).setOnClickListener {
            showAboutDialog()
        }

        findViewById<View>(R.id.quit_button).setOnClickListener {
            finishAffinity()

            System.exit(0)
        }



    }


    private fun onEncryptClicked() {
        try {
            val plaintext = textInput.text.toString()
            val passphrase = passphraseInput.text.toString()

            if (plaintext.isEmpty() || passphrase.isEmpty()) {
                showErrorDialog("Input Error", "Text and passphrase fields cannot be empty.")
                return
            }

            val reversedPassphrase = passphrase.reversed()

            val iv = if (reversedPassphrase.length >= 16) {
                reversedPassphrase.substring(0, 16)
            } else {
                reversedPassphrase.padEnd(16, '\u0000')
            }

            val key = hashPassphrase(passphrase)
            val encryptedText = encrypt(plaintext, key, iv)

            outputText.text = encryptedText
        } catch (e: Exception) {
            showErrorDialog("Encryption Error", "An error occurred during encryption: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun onDecryptClicked() {
        try {
            val encryptedText = textInput.text.toString()
            val passphrase = passphraseInput.text.toString()

            if (encryptedText.isEmpty() || passphrase.isEmpty()) {
                showErrorDialog("Input Error", "Ciphertext and passphrase fields cannot be empty.")
                return
            }

            val reversedPassphrase = passphrase.reversed()

            val iv = if (reversedPassphrase.length >= 16) {
                reversedPassphrase.substring(0, 16)
            } else {
                reversedPassphrase.padEnd(16, '\u0000')
            }

            val key = hashPassphrase(passphrase)

            // Try to decrypt the ciphertext
            val decryptedText = decrypt(encryptedText, key, iv)
            outputText.text = decryptedText

        } catch (e: Exception) {
            showErrorDialog("Decryption Error", "An error occurred during decryption: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun showAboutDialog() {
        val inflater = layoutInflater
        val dialogLayout = inflater.inflate(R.layout.dialog_custom, null)
        val builder = AlertDialog.Builder(this)
        builder.setView(dialogLayout)
        builder.setPositiveButton("Close", null)
        builder.show()
    }

    private fun hashPassphrase(passphrase: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(passphrase.toByteArray(StandardCharsets.UTF_8)).copyOfRange(0, 16)
    }

    private fun encrypt(plaintext: String, key: ByteArray, iv: String): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(iv.toByteArray(StandardCharsets.UTF_8))
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        val encrypted = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    private fun decrypt(ciphertext: String, key: ByteArray, iv: String): String {
        try {
            val decodedCiphertext = Base64.decode(ciphertext, Base64.NO_WRAP)

            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(key, "AES")
            val ivSpec = IvParameterSpec(iv.toByteArray(StandardCharsets.UTF_8))
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

            val decryptedBytes = cipher.doFinal(decodedCiphertext)
            return String(decryptedBytes, StandardCharsets.UTF_8)

        } catch (e: Exception) {
            throw Exception("Decryption failed: ${e.message}")
        }
    }

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
        if (clipboard.hasPrimaryClip() && clipboard.primaryClipDescription?.hasMimeType(
                ClipDescription.MIMETYPE_TEXT_PLAIN) == true) {
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