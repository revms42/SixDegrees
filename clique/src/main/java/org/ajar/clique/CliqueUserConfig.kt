package org.ajar.clique

import android.content.Context
import android.util.Base64
import org.ajar.clique.database.CliqueAccount
import org.ajar.clique.database.CliqueKey
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.ajar.clique.encryption.EncryptionDescription
import org.ajar.clique.encryption.SymmetricEncryptionDescription
import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object CliqueUserConfig {

    internal var symmetricDescription = SymmetricEncryptionDescription.default

    private var _user: String? = null

    private var _symKey: SecretKey? = null

    private fun initCipher(desc: EncryptionDescription, mode: Int, key: Key): Cipher {
        val cipher  = Cipher.getInstance(desc.cipher, CliqueConfig.provider)
        cipher.init(mode, key)
        return cipher
    }

    private fun byteArrayToEncodedString(byteArray: ByteArray, cipher: Cipher): String =
            Base64.encodeToString(cipher.doFinal(byteArray), Base64.NO_WRAP)

    private fun stringToEncodedString(string: String, cipher: Cipher): String =
            Base64.encodeToString(cipher.doFinal(string.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)

    fun loadUser(user: String, context: Context) {
        CliqueConfig.getPrivateKeyFromKeyStore(user)?.also { userKey ->
            val encryptCipher  = fun():Cipher { return initCipher(CliqueConfig.assymetricEncryption, Cipher.ENCRYPT_MODE, userKey) }

            _user = stringToEncodedString(user, encryptCipher.invoke())

            if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName) //TODO: Check the return. Deal with errors.

            val encryptedSym = SecureDatabase.instance?.accountDao()?.findSymmetricDesc(user)
            encryptedSym?.also {
                val decryptCipher = fun():Cipher { return initCipher(CliqueConfig.assymetricEncryption, Cipher.DECRYPT_MODE, userKey) }
                val symBytes = Base64.decode(it.symKey, Base64.NO_WRAP)
                val decryptedSymBytes = decryptCipher.invoke().doFinal(symBytes)

                val symAlgoBytes = Base64.decode(it.symAlgo, Base64.NO_WRAP)
                val decryptedAlgoBytes = decryptCipher.invoke().doFinal(symAlgoBytes)

                symmetricDescription = SymmetricEncryptionDescription.fromString(decryptedAlgoBytes.toString(Charsets.UTF_8))
                _symKey = SecretKeySpec(decryptedSymBytes, symmetricDescription.cipher)
            }
        }
    }

    fun createUser(user: String, displayName: String, encryption: AsymmetricEncryptionDescription, url: String, context: Context) {
        CliqueConfig.createSecuredKeyInKeyStore(user).private.also { userKey ->
            val encryptUserKey = fun (): Cipher { return initCipher(CliqueConfig.assymetricEncryption, Cipher.ENCRYPT_MODE, userKey) }

            _user = stringToEncodedString(user, encryptUserKey.invoke())

            val generator = KeyGenerator.getInstance(symmetricDescription.algorithm)
            val random = SecureRandom()
            generator.init(symmetricDescription.keySize, random)

            _symKey = generator.generateKey()
            val encryptSymKey = fun (): Cipher { return initCipher(symmetricDescription, Cipher.ENCRYPT_MODE, _symKey!!) }

            val encryptSym = byteArrayToEncodedString(_symKey!!.encoded, encryptUserKey.invoke())

            val encryptSymAlgo = stringToEncodedString(symmetricDescription.toString(), encryptUserKey.invoke())

            val encDisplayName = stringToEncodedString(displayName, encryptSymKey.invoke())

            val filter = stringToEncodedString(user, encryptSymKey.invoke())

            val encUrl = stringToEncodedString(url, encryptSymKey.invoke())

            val algoDescEncrypted = encryption.toString()
            val encryptionOne = "$user:feed"
            val encryptOnePair = CliqueConfig.createKeyPair(encryptionOne, encryption)

            val encryptOnePublic = byteArrayToEncodedString(encryptOnePair.public.encoded, encryptSymKey.invoke())
            val feedPublic = stringToEncodedString("$encryptionOne(public)", encryptSymKey.invoke())
            val feedPublicKey = CliqueKey(feedPublic, encryptOnePublic, algoDescEncrypted)

            val encryptOnePrivate = byteArrayToEncodedString(encryptOnePair.private.encoded, encryptSymKey.invoke())
            val feedPrivate = stringToEncodedString("$encryptionOne(private)", encryptSymKey.invoke())
            val feedPrivateKey = CliqueKey(feedPrivate, encryptOnePrivate, algoDescEncrypted)

            val encryptionTwo = "$user:garbage"
            val encryptTwoPair = CliqueConfig.createKeyPair(encryptionTwo, encryption)

            val encryptTwoPublic = byteArrayToEncodedString(encryptTwoPair.public.encoded, encryptSymKey.invoke())
            val garbage = stringToEncodedString("$encryptionTwo(public)", encryptSymKey.invoke())
            val garbagePublicKey = CliqueKey(garbage, encryptTwoPublic, algoDescEncrypted)

            if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName)

            //TODO: Create the public and private feed keys, and the private 2 garbage.

            val cliqueAccount = CliqueAccount(_user!!, encDisplayName, filter, feedPublic, feedPrivate, garbage, encryptSym, encryptSymAlgo, encUrl)
            SecureDatabase.instance!!.accountDao().addAccount(cliqueAccount)

            SecureDatabase.instance!!.keyDao().addKey(feedPublicKey)
            SecureDatabase.instance!!.keyDao().addKey(feedPrivateKey)
            SecureDatabase.instance!!.keyDao().addKey(garbagePublicKey)
        }
    }
}