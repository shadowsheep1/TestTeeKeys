package com.example.testteekeys

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.navigation.fragment.findNavController
import com.example.testteekeys.databinding.FragmentFirstBinding
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class FirstFragment : Fragment() {

    private var _binding: FragmentFirstBinding? = null

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
            findNavController().navigate(R.id.action_FirstFragment_to_SecondFragment)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            var keyPair = getKeyPair()
            if (keyPair == null) {
                keyPair = generateKeyPair()
            }
            printKeyInfo(keyPair.private)
            println("privateKey: ${keyPair.private}, publicKey: ${keyPair.public}")
        } else {
            Toast.makeText(requireContext(), "Cannot use KeyStore", Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun printKeyInfo(key: PrivateKey) {
        val factory = KeyFactory.getInstance(
            key.algorithm,
            KeyConfig.EC_P_256.provider)
        val keyInfo: KeyInfo
        try {
            keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
            println("Alias: ${keyInfo.keystoreAlias}")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
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
            KeyProperties.KEY_ALGORITHM_EC, KeyConfig.EC_P_256.provider
        )
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(
                KeyConfig.EC_P_256.alias, KeyProperties.PURPOSE_SIGN
            ).setAlgorithmParameterSpec(
                    ECGenParameterSpec(KeyConfig.EC_P_256.algorithm)
                ).setDigests(
                    KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA384,
                    KeyProperties.DIGEST_SHA512
                )
                // Only permit the private key to be used if the user authenticated
                // within the last five minutes.
                //.setUserAuthenticationRequired(true)
                //.setUserAuthenticationValidityDurationSeconds(5 * 60)
                .build()
        )
        val keyPair = keyPairGenerator.generateKeyPair()
        val signature = Signature.getInstance(KeyConfig.EC_P_256.signature)
        signature.initSign(keyPair.private)

        return keyPair
    }

    private fun getKeyPair(): KeyPair? {
        // The key pair can also be obtained from the Android Keystore any time as follows:
        val keyStore = KeyStore.getInstance(KeyConfig.EC_P_256.provider)
        keyStore.load(null)
        val privateKey = keyStore.getKey(KeyConfig.EC_P_256.alias, null) as? PrivateKey
        privateKey?.also {
            val publicKey = keyStore.getCertificate(KeyConfig.EC_P_256.alias).publicKey
            return KeyPair(publicKey, it)
        }
        return null
    }

    companion object {
        private enum class KeyConfig(
            val alias: String, val algorithm: String, val signature: String, val provider: String
        ) {
            EC_P_256(
                alias = "key1",
                algorithm = "secp256r1",
                signature = "SHA256withECDSA",
                provider = "AndroidKeyStore"
            )
        }
    }
}