package org.ajar.clique

import android.util.Base64
import android.util.Log
import org.ajar.clique.encryption.*
import java.lang.Exception
import java.security.*
import javax.crypto.Cipher

object CliqueConfig {
    //TODO: Make configurable?
    internal var keyStoreType: String = "AndroidKeyStore"
    internal var dbName: String = "CliqueDatabase"
    internal var provider: Provider? = null
    private var keyStore: KeyStore? = null
//
//    private var createSpecBuilder: (String, Int) -> KeyGenParameterSpec.Builder = KeyGenParameterSpec::Builder
//    private var createKeyPairGenerator: (String, String?) -> KeyPairGenerator = KeyPairGenerator::getInstance

    private var encodeToString: (ByteArray, Int) -> String = Base64::encodeToString
    private var decodeToByteArray: (String, Int) -> ByteArray = Base64::decode
//    private var createSecureRandom: () -> SecureRandom = ::SecureRandom

    private var _tableNameEncryption: SymmetricEncryption? = null
    internal var tableNameEncryption: SymmetricEncryption
        get() {
            if(_tableNameEncryption == null) {
                _tableNameEncryption = SymmetricEncryptionDesc.DEFAULT
            }
            return _tableNameEncryption!!
        }
        set(value) {
            this._tableNameEncryption = value
        }
//
//    fun privateKeyFromBytes(algorithm: String, keyBytes: ByteArray): PrivateKey {
//        val factory = KeyFactory.getInstance(algorithm, provider)
//        return factory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
//    }
//
//    fun publicKeyFromBytes(algorithm: String, keyBytes: ByteArray): PublicKey {
//        val factory = KeyFactory.getInstance(algorithm, provider)
//        return factory.generatePublic(X509EncodedKeySpec(keyBytes))
//    }
//
//    fun initCipher(desc: EncryptionDescription, mode: Int, key: Key): Cipher {
//        val cipher  = Cipher.getInstance(desc.cipher, provider)
//        cipher.init(mode, key)
//        return cipher
//    }

    fun transcodeString(string: String, readCipher: Cipher, writeCipher: Cipher): String {
        return stringToEncodedString(encodedStringToString(string, readCipher), writeCipher)
    }

    fun byteArrayToEncodedString(byteArray: ByteArray, cipher: Cipher): String =
            encodeToString(cipher.doFinal(byteArray), Base64.NO_WRAP)


    fun encodedStringToByteArray(encodedString: String, cipher: Cipher): ByteArray =
            cipher.doFinal(decodeToByteArray(encodedString, Base64.NO_WRAP))

    fun stringToEncodedString(string: String, cipher: Cipher): String =
            byteArrayToEncodedString(string.toByteArray(Charsets.UTF_8), cipher)

    fun encodedStringToString(encodedString: String, cipher: Cipher): String =
            String(encodedStringToByteArray(encodedString, cipher), Charsets.UTF_8)

    internal fun loadKeyStore(loadParams: KeyStore.LoadStoreParameter? = null) {
       val keyStore = KeyStore.getInstance(keyStoreType, provider)

        keyStore!!.load(loadParams)
        this.keyStore = keyStore
    }

    internal fun saveKeyStore(saveParams: KeyStore.LoadStoreParameter? = null) {
        keyStore?.store(saveParams)
    }

    internal fun setKeyStore(keyStore: KeyStore) {
        this.keyStore = keyStore
    }

    internal fun getKeyStore(): KeyStore? {
        if(keyStore == null)  {
            try {
                loadKeyStore()
            } catch (e: Exception) {
                Log.e("CliqueConfig", "Error loading keystore $keyStoreType", e)
            }
        }

        return keyStore
    }
//
//    internal fun setKeySpecBuilder(specBuilder: (String, Int) -> KeyGenParameterSpec.Builder) {
//        this.createSpecBuilder = specBuilder
//    }
//
//    internal fun setKeyPairGeneratorCreator(keyPairGenerator: (String, String?) -> KeyPairGenerator) {
//        this.createKeyPairGenerator = keyPairGenerator
//    }
//
//    internal fun setSecureRandomeCreator(secureRandomCreator: () -> SecureRandom) {
//        this.createSecureRandom = secureRandomCreator
//    }

    internal fun setStringEncoder(stringEncoder: (ByteArray, Int) -> String) {
        this.encodeToString = stringEncoder
    }

    internal fun setByteArrayDecoder(byteArrayDecoder: (String, Int) -> ByteArray) {
        this.decodeToByteArray = byteArrayDecoder
    }

    //TODO: Default values are probably not a good idea.
//    internal fun createKeyPair(
//            name: String,
//            description: AsymmetricEncryptionDescription = tableNameEncryption
//    ): KeyPair {
//        return generateKeyPair(description.algorithm, createKeyBuilder(name, description.blockMode, description.padding, description.keySize, description.requireRandom).build(), null)
//    }
//
//    internal fun createSecuredKeyInKeyStore(
//            name: String,
//            description: AsymmetricEncryptionDescription = tableNameEncryption
//    ): KeyPair {
//        return generateKeyPair(description.algorithm, createProtectedKeyBuilder(name, description.blockMode, description.padding, description.keySize, description.requireRandom).build(), keyStoreType)
//    }
//
//    internal fun createSecretKey(symKeyDescription: SymmetricEncryptionDescription = SymmetricEncryptionDescription.default, provider: Provider? = this.provider) : SecretKey {
//        val generator = KeyGenerator.getInstance(symKeyDescription.algorithm, provider)
//
//        val secureRandom = createSecureRandom.invoke()
//        generator.init(symKeyDescription.keySize, secureRandom)
//
//        return generator.generateKey()
//    }

//    private fun createKeyBuilder(
//            name: String,
//            blockModes: String,
//            padding: String,
//            keySize: Int,
//            requireRandom: Boolean
//    ): KeyGenParameterSpec.Builder {
//        val builder = createSpecBuilder.invoke(name, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
//                .setBlockModes(blockModes)
//                .setEncryptionPaddings(padding)
//                .setRandomizedEncryptionRequired(requireRandom)
//
//        takeIf { keySize > 0 }.also { builder.setKeySize(keySize) }
//        return builder
//    }
//
//    private fun createProtectedKeyBuilder(
//            name: String,
//            blockModes: String,
//            padding: String,
//            keySize: Int,
//            requireRandom: Boolean
//    ): KeyGenParameterSpec.Builder {
//        val builder = createKeyBuilder(name, blockModes, padding, keySize, requireRandom)
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
//            builder.setUnlockedDeviceRequired(true)
//            builder.setUserPresenceRequired(true)
//            builder.setUserConfirmationRequired(true)
//            builder.setUserAuthenticationValidWhileOnBody(true)
//            builder.setUserAuthenticationValidityDurationSeconds(15 * 60)
//        }
//        builder.setUserAuthenticationRequired(true)
//
//        return builder
//    }

//    private fun generateKeyPair(algorithm: String, keySpec: KeyGenParameterSpec, keyStore: String?) : KeyPair {
//        val keyPairGenerator = createKeyPairGenerator.invoke(algorithm, keyStore)
//
//        keyPairGenerator.initialize(keySpec)
//
//        return keyPairGenerator.generateKeyPair()
//    }
//
    internal fun getSecretKeyFromKeyStore(name: String, password: String): Key? {
        return try {
            keyStore?.getKey(name, password.toCharArray())
        } catch (e: Exception) {
            null
        }
    }

    internal fun getPrivateKeyFromKeyStore(name: String, password: String): Key? {
        return try {
            keyStore?.getKey(name, password.toCharArray())
        } catch (e: Exception) {
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