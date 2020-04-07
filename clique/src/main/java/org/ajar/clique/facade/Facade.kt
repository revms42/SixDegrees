package org.ajar.clique.facade

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.Transformations
import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.*
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.ajar.clique.encryption.SymmetricEncryptionDescription
import org.ajar.clique.transaction.SubscriptionExchange
import javax.crypto.Cipher
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


/**
 * Representation of the user of the current account.
 * @param name unencrypted user name associated with the AndroidKeyStore's RSA key used to encrypt the user's data.
 * @param filter the user name encrypted with the user's symmetric encryption, used to filter friends from the database.
 * @param url the publication url of this user encrypted with the user's symmetric encryption.
 * @param invitationInfo a CliqueSubscription which represents a portion of the information needed to create an invitation.
 * @param symCipher a function that will initialize a cipher to encrypt or decrypt the user's symmetric key encryption.
 * @param feed a function that encrypts the given plain-text into a string using this user's asymmetric publish key.
 */
class User private constructor(
        val name: String,
        val url: String,
        internal val filter: String,
        internal val invitationInfo: () -> CliqueSubscription?,
        internal val symCipher: (Int) -> Cipher?,
        private val feed: (value: String) -> String?,
        private val androidKeyStoreAsymCipher: (Int) -> Cipher?,
        private val symKeyTag: String
){
    fun writeFeedMessage(message: String): String? = feed(message)

    private var _friends: LiveData<List<Friend>?>? = null
    val friends : LiveData<List<Friend>?>?
        get() {
            if(_friends == null) {
                _friends = SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(filter)?.let { liveData ->
                    Transformations.map(liveData) { friendsList ->
                        friendsList?.map { friend -> Friend.fromSubscription(friend, symCipher) }
                    }
                }
            }
            return _friends
        }

    internal fun addFriend(friendInfo: SubscriptionExchange.FriendInfo) {
        val friendName = CliqueConfig.encodedStringToString(friendInfo.name!!, symCipher.invoke(Cipher.DECRYPT_MODE)!!)

        val appendTo = fun(append: String): String {
            return CliqueConfig.stringToEncodedString("$friendName:$append", symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        }

        val publicOneName = appendTo("publicOne")
        val privateOneName = appendTo("privateOne")
        val publicTwoName = appendTo("publicTwo")

        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(publicOneName, friendInfo.readKey!!, friendInfo.readAlgo!!))
        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(privateOneName, friendInfo.privateOne!!, friendInfo.privateOneAlgo!!))
        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(publicTwoName, friendInfo.publicTwo!!, friendInfo.publicTwoAlgo!!))

        val dbName = CliqueConfig.stringToEncodedString(friendName, androidKeyStoreAsymCipher.invoke(Cipher.ENCRYPT_MODE)!!)

        val symKey = SecureDatabase.instance?.accountDao()?.findSymmetricDesc(symKeyTag)

        SecureDatabase.instance?.accountDao()?.addAccount(CliqueAccount(
                dbName,
                friendName,
                filter,
                publicOneName,
                privateOneName,
                publicTwoName,
                symKey!!.symKey,
                symKey.symAlgo,
                friendInfo.url!!
        ))
    }

    companion object {
        fun loadUser(context: Context, user: String): User? {
            return CliqueConfig.getPrivateKeyFromKeyStore(user)?.let { userKey ->
                val asymCipher = fun(mode: Int): Cipher { return CliqueConfig.initCipher(CliqueConfig.assymetricEncryption, mode, userKey) }

                val encodedName = CliqueConfig.stringToEncodedString(user, asymCipher.invoke(Cipher.ENCRYPT_MODE))

                if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName) //TODO: Check the return. Deal with errors.

                val encryptedSym = SecureDatabase.instance?.accountDao()?.findSymmetricDesc(encodedName)
                encryptedSym?.let {
                    val symCipher = fun(mode: Int): Cipher? { return symDescToCipher(encodedName, mode, asymCipher) }

                    val feedWriter = fun(value: String): String? { return writeFeedMessage(encodedName, value, symCipher) }

                    val friendRequestInfo = fun(): CliqueSubscription? { return SecureDatabase.instance?.accountDao()?.findFriendRequestInfo(encodedName) }

                    val filter = SecureDatabase.instance?.accountDao()?.findFilterForUser(encodedName)!!

                    val encryptedPublishUrl = SecureDatabase.instance?.accountDao()?.findPublishUrlForUser(encodedName)

                    User(
                            user,
                            filter,
                            CliqueConfig.encodedStringToString(encryptedPublishUrl!!, symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                            friendRequestInfo,
                            symCipher,
                            feedWriter,
                            asymCipher,
                            encodedName
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

                val symKey = CliqueConfig.createSecretKey(symmetricDescription)
                val encryptSymKey = fun (): Cipher { return CliqueConfig.initCipher(symmetricDescription, Cipher.ENCRYPT_MODE, symKey!!) }

                val encryptSym = CliqueConfig.byteArrayToEncodedString(symKey.encoded, encryptUserKey.invoke())

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

                val cliqueAccount = CliqueAccount(encodedUser, encDisplayName, filter, feedPublic, feedPrivate, garbage, encryptSym, encryptSymAlgo, encUrl)
                SecureDatabase.instance!!.accountDao().addAccount(cliqueAccount)

                SecureDatabase.instance!!.keyDao().addKey(feedPublicKey)
                SecureDatabase.instance!!.keyDao().addKey(feedPrivateKey)
                SecureDatabase.instance!!.keyDao().addKey(garbagePublicKey)
            }
        }
    }
}

/**
 * This is a representation of a subscription that is used to retrieve feed information for a user.
 * @param displayName unencoded friend display name
 * @param url unencoded url
 * @param asymCipher function that generates a decrypting cipher to read the friend'ss publications.
 */
class Friend private constructor(val displayName: String, val url: String, private val asymCipher: () -> Cipher?){

    /**
     * Take raw encoded feed information and decrypt it.
     * @param feed encoded feed information for this friend.
     */
    fun decryptFeed(feed: String): String {
        return CliqueConfig.encodedStringToString(feed, asymCipher.invoke()!!)
    }

    companion object {
        /**
         * @param subscription user symmetric encrypted subscription information for the friend
         * @param symDecrypt function that generates a decryption cipher for the encryption used to encrypt the subscription.
         */
        internal fun fromSubscription(subscription: CliqueSubscription, symCipher: (Int) -> Cipher?): Friend {
            // To create this friend we need to get the display name, url, and read key and turn them
            // into something we can use: A display name, url, and function that creates a read cipher for
            // the url.
            return Friend(
                    CliqueConfig.encodedStringToString(subscription.subscriber, symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                    CliqueConfig.encodedStringToString(subscription.subscription, symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                    fun() : Cipher? {
                        return cliqueKeyToCipher(subscription.feedReadKey, Cipher.DECRYPT_MODE, symCipher)
                    }
            )
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