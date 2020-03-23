package org.ajar.clique

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.gson.Gson
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import java.lang.Exception
import java.security.*

object CliqueConfig {
    internal val targetCharset = Charsets.UTF_8
    internal val gson = Gson()
    //TODO: Make configurable?
    internal var keyStoreType: String = "AndroidKeyStore"
    internal var dbName: String = "CliqueDatabase"
    internal var provider: Provider? = null
    private var keyStore: KeyStore? = null

    internal var assymetricEncryption = AsymmetricEncryptionDescription.default

    internal fun loadKeyStore(loadParams: KeyStore.LoadStoreParameter? = null) {
        keyStore = KeyStore.getInstance(keyStoreType, provider)

        keyStore!!.load(loadParams)
    }

    internal fun saveKeyStore(saveParams: KeyStore.LoadStoreParameter? = null) {
        keyStore?.store(saveParams)
    }

    //TODO: Default values are probably not a good idea.
    internal fun createKeyPair(
            name: String,
            description: AsymmetricEncryptionDescription = assymetricEncryption
    ): KeyPair {
        return generateKeyPair(description.algorithm, createKeyBuilder(name, description.blockMode, description.padding, description.requireRandom).build(), null)
    }

    internal fun createSecuredKeyInKeyStore(
            name: String,
            description: AsymmetricEncryptionDescription = assymetricEncryption
    ): KeyPair {
        return generateKeyPair(description.algorithm, createProtectedKeyBuilder(name, description.blockMode, description.padding, description.requireRandom).build(), keyStoreType)
    }

    private fun createKeyBuilder(
            name: String,
            blockModes: String,
            padding: String,
            requireRandom: Boolean
    ): KeyGenParameterSpec.Builder {
            return KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
                    .setBlockModes(blockModes)
                    .setEncryptionPaddings(padding)
                    .setRandomizedEncryptionRequired(requireRandom)
    }

    private fun createProtectedKeyBuilder(
            name: String,
            blockModes: String,
            padding: String,
            requireRandom: Boolean
    ): KeyGenParameterSpec.Builder {
        val builder = createKeyBuilder(name, blockModes, padding, requireRandom)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
            builder.setUserPresenceRequired(true)
            builder.setUserConfirmationRequired(true)
            builder.setUserAuthenticationValidWhileOnBody(true)
            builder.setUserAuthenticationValidityDurationSeconds(15 * 60)
        }
        builder.setUserAuthenticationRequired(true)

        return builder
    }

    private fun generateKeyPair(algorithm: String, keySpec: KeyGenParameterSpec, keyStore: String?) : KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm, keyStore)

        keyPairGenerator.initialize(keySpec)

        return keyPairGenerator.generateKeyPair()
    }

    internal fun getPrivateKeyFromKeyStore(name: String): Key? {
        return try {
            keyStore?.getKey(name, null)
        } catch (_: Exception) {
            null
        }
    }

    internal fun getPublicKeyFromKeyStore(name: String): Key? {
        return try {
            keyStore?.getCertificate(name)?.publicKey
        } catch (_: Exception) {
            null
        }
    }
}