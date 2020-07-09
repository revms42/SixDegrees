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

    private var encodeToString: (ByteArray, Int) -> String = Base64::encodeToString
    private var decodeToByteArray: (String, Int) -> ByteArray = Base64::decode

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

    internal fun setStringEncoder(stringEncoder: (ByteArray, Int) -> String) {
        this.encodeToString = stringEncoder
    }

    internal fun setByteArrayDecoder(byteArrayDecoder: (String, Int) -> ByteArray) {
        this.decodeToByteArray = byteArrayDecoder
    }

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