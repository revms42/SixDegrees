package org.ajar.clique.facade

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.Transformations
import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.*
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.ajar.clique.encryption.SymmetricEncryptionDescription
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

private fun symDescToCipher(name: String, mode: Int, asymCipher: (Int) -> Cipher): Cipher? {
    return SecureDatabase.instance?.accountDao()?.findSymmetricDesc(name)?.let {
        val symAlgoDesc =
                SymmetricEncryptionDescription.fromString(
                        CliqueConfig.encodedStringToString(it.symAlgo, asymCipher.invoke(Cipher.DECRYPT_MODE))
                )

        return CliqueConfig.initCipher(
                symAlgoDesc,
                mode,
                SecretKeySpec(
                        CliqueConfig.encodedStringToByteArray(it.symKey, asymCipher.invoke(Cipher.DECRYPT_MODE)),
                        symAlgoDesc.cipher
                )
        )
    }
}

private fun cliqueKeyToCipher(name: String, mode: Int, symCipher: (Int) -> Cipher?): Cipher? {
    return SecureDatabase.instance?.keyDao()?.findKey(name)?.let {
        val keyAlgoDesc =
                AsymmetricEncryptionDescription.fromString(
                        CliqueConfig.encodedStringToString(it.cipher, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
                )

        CliqueConfig.initCipher(
                keyAlgoDesc,
                mode,
                CliqueConfig.privateKeyFromBytes(
                        keyAlgoDesc.algorithm,
                        CliqueConfig.encodedStringToByteArray(it.key, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
                )
        )
    }
}

private fun writeFeedMessage(name: String, message: String, symCipher: (Int) -> Cipher?): String? {
    return SecureDatabase.instance?.accountDao()?.findPublishKey(name)?.let {
        return CliqueConfig.stringToEncodedString(message,
                cliqueKeyToCipher(it, Cipher.ENCRYPT_MODE, symCipher)!!
        )
    }
}

private fun getSubscriptionInvitation(name: String): Invitation? {
    return Invitation.fromSubscription(SecureDatabase.instance?.accountDao()?.findFriendRequestInfo(name)!!)
}

class Invitation private constructor(val displayName: String, val url: String, val readKey: String, val algo: String, val encoded: Boolean) {

    fun transcode(readCipher: () -> Cipher, writeCipher: () -> Cipher): Invitation {
        return Invitation(
                CliqueConfig.transcodeString(displayName, readCipher.invoke(), writeCipher.invoke()),
                CliqueConfig.transcodeString(url, readCipher.invoke(), writeCipher.invoke()),
                CliqueConfig.transcodeString(readKey, readCipher.invoke(), writeCipher.invoke()),
                CliqueConfig.transcodeString(algo, readCipher.invoke(), writeCipher.invoke()),
                true
        )
    }

    companion object {
        internal fun fromSubscription(subscription: CliqueSubscription) : Invitation {
            val feedKey = SecureDatabase.instance?.keyDao()?.findKey(subscription.feedReadKey)
            return Invitation(subscription.subscriber, subscription.subscription, feedKey!!.key, feedKey.cipher, true)
        }
    }
}

class RotationMessage private constructor(val algo: String, val url: String, val key: String) {

    override fun toString(): String {
        TODO("Make Serialization Possible!")
    }

    companion object {
        internal fun create(algo: String, url: String, key: String): RotationMessage {
            return RotationMessage(algo, url, key)
        }

        internal fun fromString(serializedRotation: String): RotationMessage {
            TODO("Make Deserialization Possible")
        }
    }
}

class User private constructor(
        val name: String,
        val url: String,
        val friends: LiveData<List<Friend>?>,
        val rotation: LiveData<List<Rotation>?>,
        private val subscribe: () -> Invitation?,
        private val feed: (value: String) -> String?
){
    fun writeFeedMessage(message: String): String? = feed(message)
    fun getSubscriptionInvitation(): Invitation? = subscribe()

    companion object {
        fun loadUser(user: String, context: Context): User? {
            return CliqueConfig.getPrivateKeyFromKeyStore(user)?.let { userKey ->
                val asymCipher = fun(mode: Int): Cipher { return CliqueConfig.initCipher(CliqueConfig.assymetricEncryption, mode, userKey) }

                val encodedName = CliqueConfig.stringToEncodedString(user, asymCipher.invoke(Cipher.ENCRYPT_MODE))

                if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName) //TODO: Check the return. Deal with errors.

                val encryptedSym = SecureDatabase.instance?.accountDao()?.findSymmetricDesc(encodedName)
                encryptedSym?.let {
                    val symCipher = fun(mode: Int): Cipher? { return symDescToCipher(encodedName, mode, asymCipher) }

                    val feedWriter = fun(value: String): String? { return writeFeedMessage(encodedName, value, symCipher) }
                    val subscriptionWriter = fun(): Invitation? { return getSubscriptionInvitation(encodedName) }

                    val filter = SecureDatabase.instance?.accountDao()?.findFilterForUser(encodedName)

                    /** Note: Big assumption here - we're assuming that the dao will always return a non-null list.**/
                    val friends = Transformations.map(SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(filter!!)!!) { subscriptionList ->
                        subscriptionList?.map { subscription ->
                            Friend.fromSubscription(subscription, fun(): Cipher? { return symCipher(Cipher.DECRYPT_MODE) } )
                        }
                    }

                    val encryptedPublishUrl = SecureDatabase.instance?.accountDao()?.findPublishUrlForUser(encodedName)
                    val rotation = Transformations.map(SecureDatabase.instance?.accountDao()?.findRotationKeys(filter!!)!!) { rotationList ->
                        rotationList?.map { rotation ->
                            Rotation.fromRotationDescription(rotation, encryptedPublishUrl!!, symCipher)
                        }
                    }

                    User(
                            user,
                            CliqueConfig.encodedStringToString(encryptedPublishUrl!!, symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                            friends,
                            rotation,
                            subscriptionWriter,
                            feedWriter
                    )
                }
            }
        }

        fun createUser(
                context: Context,
                user: String,
                displayName: String,
                url: String,
                symmetricDescription: SymmetricEncryptionDescription = SymmetricEncryptionDescription.default,
                encryption: AsymmetricEncryptionDescription = AsymmetricEncryptionDescription.default
        ) {
            CliqueConfig.createSecuredKeyInKeyStore(user).private.also { userKey ->
                val encryptUserKey = fun (): Cipher { return CliqueConfig.initCipher(CliqueConfig.assymetricEncryption, Cipher.ENCRYPT_MODE, userKey) }

                val encodedUser = CliqueConfig.stringToEncodedString(user, encryptUserKey.invoke())

                val generator = KeyGenerator.getInstance(symmetricDescription.algorithm, CliqueConfig.provider)
                //TODO: Determine if this needs to be configurable or "strong"
                val random = SecureRandom()
                generator.init(symmetricDescription.keySize, random)

                val symKey = generator.generateKey()
                val encryptSymKey = fun (): Cipher { return CliqueConfig.initCipher(symmetricDescription, Cipher.ENCRYPT_MODE, symKey!!) }

                val encryptSym = CliqueConfig.byteArrayToEncodedString(symKey!!.encoded, encryptUserKey.invoke())

                val encryptSymAlgo = CliqueConfig.stringToEncodedString(symmetricDescription.toString(), encryptUserKey.invoke())

                val encDisplayName = CliqueConfig.stringToEncodedString(displayName, encryptSymKey.invoke())

                val filter = CliqueConfig.stringToEncodedString(user, encryptSymKey.invoke())

                val encUrl = CliqueConfig.stringToEncodedString(url, encryptSymKey.invoke())

                val encryptionOne = "$user:feed"
                val encryptOnePair = CliqueConfig.createKeyPair(encryptionOne, encryption)

                val algoDescEncrypted = CliqueConfig.stringToEncodedString(encryption.algorithm, encryptSymKey.invoke())

                val encryptOnePublic = CliqueConfig.byteArrayToEncodedString(encryptOnePair.public.encoded, encryptSymKey.invoke())
                val feedPublic = CliqueConfig.stringToEncodedString("$encryptionOne(public)", encryptSymKey.invoke())
                val feedPublicKey = CliqueKey(feedPublic, encryptOnePublic, algoDescEncrypted)

                val encryptOnePrivate = CliqueConfig.byteArrayToEncodedString(encryptOnePair.private.encoded, encryptSymKey.invoke())
                val feedPrivate = CliqueConfig.stringToEncodedString("$encryptionOne(private)", encryptSymKey.invoke())
                val feedPrivateKey = CliqueKey(feedPrivate, encryptOnePrivate, algoDescEncrypted)

                val encryptionTwo = "$user:garbage"
                val encryptTwoPair = CliqueConfig.createKeyPair(encryptionTwo, encryption)

                val encryptTwoPublic = CliqueConfig.byteArrayToEncodedString(encryptTwoPair.public.encoded, encryptSymKey.invoke())
                val garbage = CliqueConfig.stringToEncodedString("$encryptionTwo(public)", encryptSymKey.invoke())
                val garbagePublicKey = CliqueKey(garbage, encryptTwoPublic, algoDescEncrypted)

                if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName)

                //TODO: Create the public and private feed keys, and the private 2 garbage.

                val cliqueAccount = CliqueAccount(encodedUser, encDisplayName, filter, feedPublic, feedPrivate, garbage, encryptSym, encryptSymAlgo, encUrl)
                SecureDatabase.instance!!.accountDao().addAccount(cliqueAccount)

                SecureDatabase.instance!!.keyDao().addKey(feedPublicKey)
                SecureDatabase.instance!!.keyDao().addKey(feedPrivateKey)
                SecureDatabase.instance!!.keyDao().addKey(garbagePublicKey)
            }
        }
    }
}

class Friend {

    companion object {
        internal fun fromSubscription(subscription: CliqueSubscription, symDecrypt: () -> Cipher?): Friend {
            //TODO: Make friends
            return Friend()
        }
    }
}

/**
 * rotate is a cliqueKey name to subscriber encrypted rotation message transform.
 */
class Rotation private constructor(val name: String, private val rotate: (String) -> String) {

    fun rotateMessageForKey(cliqueKeyName: String): String = rotate(cliqueKeyName)

    companion object {
        internal fun fromRotationDescription(description: CliqueRotateDescription, encodedUrl: String, symCipher: (Int) -> Cipher?): Rotation {
            val name = CliqueConfig.encodedStringToString(description.subscriber, symCipher.invoke(Cipher.DECRYPT_MODE)!!)

            val rotate = fun(keyName: String): String {
                return SecureDatabase.instance?.keyDao()?.findKey(keyName)?.let { newKey ->
                    val transcode = fun (value: String): String =
                            CliqueConfig.transcodeString(
                                    value,
                                    symCipher.invoke(Cipher.DECRYPT_MODE)!!,
                                    cliqueKeyToCipher(description.rotateKey, Cipher.ENCRYPT_MODE, symCipher)!!
                            )

                    RotationMessage.create(
                            transcode(newKey.cipher),
                            transcode(encodedUrl),
                            transcode(newKey.key)
                    )
                }.toString()
            }

            return Rotation(name, rotate)
        }
    }
}