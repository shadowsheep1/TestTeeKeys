package com.example.testteekeys

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.fragment.app.Fragment
import com.example.testteekeys.databinding.FragmentFirstBinding
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 * https://android.googlesource.com/platform/frameworks/base/+/master/keystore/java/android/security/keystore/KeyProtection.java
 * https://developer.android.com/training/articles/keystore
 * isInsideSecureHw -> Api level 23 (M) - https://developer.android.com/reference/android/security/keystore/KeyInfo#isInsideSecureHardware()
 */
class FirstFragment : Fragment() {
    private var _binding: FragmentFirstBinding? = null

    @RequiresApi(Build.VERSION_CODES.M)
    private var keyConfig = KeyConfig.EC_P_256

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {

        _binding = FragmentFirstBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.buttonFirst.setOnClickListener {
            //findNavController().navigate(R.id.action_FirstFragment_to_SecondFragment)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                runExample()
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun runExample() {
        keyConfig = if (binding.ecKeyButton.isChecked) {
            KeyConfig.EC_P_256
        } else {
            KeyConfig.RSA
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            var keyPair = getKeyPair()
            if (keyPair == null) {
                keyPair = generateKeyPair()
            }
            printKeyInfo(keyPair.private)
            val base64Digest = signSampleData(keyPair.private, sampleMessage)
            val signIsVerified = verifySignature(keyPair.public, base64Digest, sampleMessage)
            println("Sign verified? $signIsVerified")
            println(
                "privateKey: ${keyPair.private.encoded}, "
                        + "publicKey: ${keyPair.public.encoded}"
            )
        } else {
            Toast.makeText(requireContext(), "Cannot use KeyStore", Toast.LENGTH_LONG).show()
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun verifySignature(
        publicKey: PublicKey,
        digest: String,
        message: String
    ): Boolean {
        val sampleDataBytes = message.toByteArray()
        val signatureAlgorithm = keyConfig.signature
        println("signature algorithm: $signatureAlgorithm")
        val st = Signature.getInstance(signatureAlgorithm)
        st.initVerify(publicKey)
        println("Public key export: ${Base64.encodeToString(publicKey.encoded, Base64.DEFAULT)}")
        println("Public key format: ${publicKey.format}")
        println("${keyConfig.hash}: ${
            Base64.encodeToString(hashString(message, keyConfig.hash), Base64.NO_WRAP)
        }")
        val digestBytes = Base64.decode(digest, Base64.NO_WRAP)
        st.update(sampleDataBytes)
        return st.verify(digestBytes)
    }

    // https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest
    private fun hashString(input: String, algorithm: String): ByteArray    {
        return MessageDigest.getInstance(algorithm)
            .digest(input.toByteArray())
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun signSampleData(privateKey: PrivateKey, message: String): String {
        val sampleDataBytes = message.toByteArray()
        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
        val signatureAlgorithm = keyConfig.signature
        println("signature algorithm: $signatureAlgorithm")
        val signatureEngine = Signature.getInstance(signatureAlgorithm)
        signatureEngine.initSign(privateKey)
        signatureEngine.update(sampleDataBytes)
        val signatureBytes = signatureEngine.sign()

        val signatureBase64 = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        println("Signature base64 = $signatureBase64")
        return signatureBase64
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun printKeyInfo(key: PrivateKey) {
        val factory = KeyFactory.getInstance(
            key.algorithm,
            keyConfig.provider
        )
        val keyInfo: KeyInfo
        try {
            keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
            println("Alias: ${keyInfo.keystoreAlias}")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // https://developer.android.com/reference/android/security/keystore/KeyProperties#SECURITY_LEVEL_SOFTWARE
                println("Hardware-backed: ${keyInfo.securityLevel}")
            } else {
                @Suppress("DEPRECATION")
                println("Hardware-backed: ${keyInfo.isInsideSecureHardware}")
            }
        } catch (e: InvalidKeySpecException) {
            Toast.makeText(
                requireContext(),
                "Cannot obtain info for this key!",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            keyConfig.algorithm,
            keyConfig.provider
        )
        val keySpec: AlgorithmParameterSpec
        KeyGenParameterSpec.Builder(
            keyConfig.alias, KeyProperties.PURPOSE_SIGN
        ).apply {
            keyConfig.algorithmParam?.let {
                if (keyConfig == KeyConfig.EC_P_256) {
                    setAlgorithmParameterSpec(ECGenParameterSpec(it))
                }
            }
            setDigests(
                KeyProperties.DIGEST_SHA256,
                //KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )
            // https://www.mail-archive.com/android-developers@googlegroups.com/msg241873.html
            // Caused by: java.security.InvalidKeyException: Keystore operation failed
            // android.security.KeyStoreException: Incompatible padding mode
            //setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            // Only permit the private key to be used if the user authenticated
            // within the last five minutes.
            //.setUserAuthenticationRequired(true)
            //.setUserAuthenticationValidityDurationSeconds(5 * 60)
            keySpec = build()
        }
        keyPairGenerator.initialize(keySpec)
        val keyPair = keyPairGenerator.generateKeyPair()
        val signature = Signature.getInstance(keyConfig.signature)
        signature.initSign(keyPair.private)

        return keyPair
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getKeyPair(): KeyPair? {
        // The key pair can also be obtained from the Android Keystore any time as follows:
        val keyStore = KeyStore.getInstance(keyConfig.provider)
        keyStore.load(null)
        val privateKey = keyStore.getKey(keyConfig.alias, null) as? PrivateKey
        privateKey?.also {
            val publicKey = keyStore.getCertificate(keyConfig.alias).publicKey
            return KeyPair(publicKey, it)
        }
        return null
    }

    companion object {
        private const val sampleMessage = "Lorem ipsum bubulo bibi!"

        @RequiresApi(Build.VERSION_CODES.M)
        private enum class KeyConfig(
            val alias: String,
            val algorithm: String,
            val algorithmParam: String?,
            val signature: String,
            val hash: String,
            val provider: String
        ) {
            EC_P_256(
                alias = "keyEC",
                algorithm = KeyProperties.KEY_ALGORITHM_EC,
                algorithmParam = "secp256r1",
                signature = "SHA256withECDSA",
                hash = "SHA-256",
                provider = "AndroidKeyStore"
            ),
            RSA(
                alias = "keyRSA",
                algorithm = KeyProperties.KEY_ALGORITHM_RSA,
                algorithmParam = null,
                signature = "SHA256withRSA/PSS",
                hash = "SHA-256",
                provider = "AndroidKeyStore"
            )
        }
    }
}