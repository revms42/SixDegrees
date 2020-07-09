package org.ajar.clique.facade

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.Transformations
import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.*
import org.ajar.clique.encryption.*
import org.ajar.clique.transaction.SubscriptionExchange
import java.security.KeyStore
import javax.crypto.Cipher

private fun symDescToCipher(name: String, mode: Int, userConfigCipher: (Int) -> Cipher): Cipher? {
    return SecureDatabase.instance?.accountDao()?.findSymmetricDesc(name)?.let {
        val desc = SymmetricEncryptionDesc.fromString(
                CliqueConfig.encodedStringToString(it.symAlgo, userConfigCipher.invoke(Cipher.DECRYPT_MODE))
        )
        CipherProvider.Symmetric(desc).cipher(
                mode,
                desc.secretKeyFromBytes(
                        CliqueConfig.encodedStringToByteArray(it.symKey, userConfigCipher.invoke(Cipher.DECRYPT_MODE))
                )
        )
    }
}

private fun cliqueKeyToAsymPrivateCipher(name: String, mode: Int, symCipher: (Int) -> Cipher?): Cipher? {
    return SecureDatabase.instance?.keyDao()?.findKey(name)?.let {
        val desc = AsymmetricEncryptionDesc.fromString(
                CliqueConfig.encodedStringToString(it.cipher, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
        )
        CipherProvider.Private(desc).cipher(
                mode,
                desc.privateKeyFromBytes(
                        CliqueConfig.encodedStringToByteArray(it.key, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
                )
        )
    }
}

private fun cliqueKeyToSymCipher(name: String, mode: Int, symCipher: (Int) -> Cipher?) : Cipher? {
    return SecureDatabase.instance?.keyDao()?.findKey(name)?.let {
        val desc = SymmetricEncryptionDesc.fromString(
                CliqueConfig.encodedStringToString(it.cipher, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
        )
        CipherProvider.Symmetric(desc).cipher(
                mode,
                desc.secretKeyFromBytes(
                        CliqueConfig.encodedStringToByteArray(it.key, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
                )
        )
    }
}

private fun writeFeedMessage(name: String, message: String, symCipher: (Int) -> Cipher?): String? {
    return SecureDatabase.instance?.accountDao()?.findPublishKey(name)?.let {
        return CliqueConfig.stringToEncodedString(message,
                cliqueKeyToAsymPrivateCipher(it, Cipher.ENCRYPT_MODE, symCipher)!!
        )
    }
}

/**
 * Representation of the user of the current account.
 * @param name unencrypted user name associated with the AndroidKeyStore's RSA key used to encrypt the user's data.
 * @param filter the user name encrypted with the user's symmetric encryption, used to filter friends from the database.
 * @param url the unencrypted publication url of this user.
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
        private val androidKeyStoreUserCipher: (Int) -> Cipher?,
        private val symKeyTag: String
){
    fun writeFeedMessage(message: String): String? = feed(message)

    private var _friends: LiveData<List<Friend>?>? = null
    val friends : LiveData<List<Friend>?>?
        get() {
            if(_friends == null) {
                _friends = SecureDatabase.instance?.accountDao()?.observeSubscriptionKeys(filter)?.let { liveData ->
                    Transformations.map(liveData) { friendsList ->
                        friendsList?.map { friend -> Friend.fromSubscription(friend, symCipher) }
                    }
                }
            }
            return _friends
        }

    internal fun addFriend(friendInfo: SubscriptionExchange.FriendInfo) {
        val friendName = CliqueConfig.encodedStringToString(friendInfo.name, symCipher.invoke(Cipher.DECRYPT_MODE)!!)

        val appendTo = fun(append: String): String {
            return CliqueConfig.stringToEncodedString("$friendName:$append", symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        }

        val rotateKey = appendTo("key1")
        val feedReadKey = appendTo("key2")

        //TODO("Make this work with the new friend info")
        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(rotateKey, friendInfo.rotateKey, friendInfo.rotateKeyAlgo))
        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(feedReadKey, friendInfo.friendReadKey, friendInfo.friendReadAlgo))

        val dbName = CliqueConfig.stringToEncodedString(friendName, androidKeyStoreUserCipher.invoke(Cipher.ENCRYPT_MODE)!!)

        val symKey = SecureDatabase.instance?.accountDao()?.findSymmetricDesc(symKeyTag)

        SecureDatabase.instance?.accountDao()?.addAccount(CliqueAccount(
                dbName,
                friendInfo.name,
                filter,
                rotateKey,
                feedReadKey,
                symKey!!.symKey,
                symKey.symAlgo,
                friendInfo.url
        ))
    }

    companion object {
        fun loadUser(context: Context, user: String, password: String): User? {
            return CliqueConfig.getSecretKeyFromKeyStore(user, password)?.let { userKey ->
                val configCipher = fun(mode: Int): Cipher { return CipherProvider.Symmetric(CliqueConfig.tableNameEncryption).cipher(mode, userKey) }

                val encodedName = CliqueConfig.stringToEncodedString(user, configCipher.invoke(Cipher.ENCRYPT_MODE))

                if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName) //TODO: Check the return. Deal with errors.

                val encryptedSym = SecureDatabase.instance?.accountDao()?.findSymmetricDesc(encodedName)
                encryptedSym?.let {
                    val symCipher = fun(mode: Int): Cipher? { return symDescToCipher(encodedName, mode, configCipher) }

                    val feedWriter = fun(value: String): String? { return writeFeedMessage(encodedName, value, symCipher) }

                    val friendRequestInfo = fun(): CliqueSubscription? { return SecureDatabase.instance?.accountDao()?.findFriendRequestInfo(encodedName) }

                    val filter = SecureDatabase.instance?.accountDao()?.findFilterForUser(encodedName)!!

                    val encryptedPublishUrl = SecureDatabase.instance?.accountDao()?.findPublishUrlForUser(encodedName)

                    User(
                            user,
                            CliqueConfig.encodedStringToString(encryptedPublishUrl!!, symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                            filter,
                            friendRequestInfo,
                            symCipher,
                            feedWriter,
                            configCipher,
                            encodedName
                    )
                }
            }
        }

        fun createUser(
                context: Context,
                user: String,
                password: String,
                displayName: String,
                url: String,
                symmetricDescription: SymmetricEncryption = SymmetricEncryptionDesc.DEFAULT,
                encryption: AsymmetricEncryption = AsymmetricEncryptionDesc.DEFAULT
        ) {
            // You could theoretically brute force the user name if you threw an exception here.
            // In theory you could *still* brute force here, it's just dependent on how long it takes to
            // set up an account.
            if(CliqueConfig.getKeyStore()?.containsAlias(user) == true) return

            CliqueConfig.tableNameEncryption.generateSecretKey(user).also { userKey ->
                CliqueConfig.getKeyStore()?.setEntry(user, KeyStore.SecretKeyEntry(userKey), KeyStore.PasswordProtection(password.toCharArray()))
                val encryptUserKey = fun (): Cipher { return CipherProvider.Symmetric(CliqueConfig.tableNameEncryption).cipher(Cipher.ENCRYPT_MODE, userKey) }

                val encodedUser = CliqueConfig.stringToEncodedString(user, encryptUserKey.invoke())

                val symKey = symmetricDescription.generateSecretKey()
                val encryptSymKey = fun (): Cipher { return CipherProvider.Symmetric(symmetricDescription).cipher(Cipher.ENCRYPT_MODE, symKey) }

                val encryptSym = CliqueConfig.byteArrayToEncodedString(symKey.encoded, encryptUserKey.invoke())

                val encryptSymAlgo = CliqueConfig.stringToEncodedString(symmetricDescription.toString(), encryptUserKey.invoke())

                val encDisplayName = CliqueConfig.stringToEncodedString(displayName, encryptSymKey.invoke())

                val filter = CliqueConfig.stringToEncodedString(user, encryptSymKey.invoke())

                val encUrl = CliqueConfig.stringToEncodedString(url, encryptSymKey.invoke())

                val feedKeyPair = generateUserFeedKeys(user, encryption, encryptSymKey)
                val feedPublic = feedKeyPair.feedPublic
                val feedPublicKey = feedKeyPair.feedPublicKey
                val feedPrivate = feedKeyPair.feedPrivate
                val feedPrivateKey = feedKeyPair.feedPrivateKey

                if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName)

                val cliqueAccount = CliqueAccount(encodedUser, encDisplayName, filter, feedPublic, feedPrivate, encryptSym, encryptSymAlgo, encUrl)
                SecureDatabase.instance!!.accountDao().addAccount(cliqueAccount)

                SecureDatabase.instance!!.keyDao().addKey(feedPublicKey)
                SecureDatabase.instance!!.keyDao().addKey(feedPrivateKey)
            }
        }

        internal fun generateUserFeedKeys(user: String, encryption: AsymmetricEncryption, encryptSymKey: () -> Cipher): FeedKeyPair {
            val encryptionOne = "$user:feed"
            val encryptOnePair = encryption.generateKeyPair(encryptionOne)

            val algoDescEncrypted = CliqueConfig.stringToEncodedString(encryption.toString(), encryptSymKey.invoke())

            val encryptOnePublic = CliqueConfig.byteArrayToEncodedString(encryptOnePair.public.encoded, encryptSymKey.invoke())
            val feedPublic = CliqueConfig.stringToEncodedString("$encryptionOne(public)", encryptSymKey.invoke())
            val feedPublicKey = CliqueKey(feedPublic, encryptOnePublic, algoDescEncrypted)

            val encryptOnePrivate = CliqueConfig.byteArrayToEncodedString(encryptOnePair.private.encoded, encryptSymKey.invoke())
            val feedPrivate = CliqueConfig.stringToEncodedString("$encryptionOne(private)", encryptSymKey.invoke())
            val feedPrivateKey = CliqueKey(feedPrivate, encryptOnePrivate, algoDescEncrypted)

            return FeedKeyPair(feedPublic, feedPublicKey, feedPrivate, feedPrivateKey)
        }
    }
}

data class FeedKeyPair(val feedPublic: String, val feedPublicKey: CliqueKey, val feedPrivate: String, val feedPrivateKey: CliqueKey)

/**
 * This is a representation of a subscription that is used to retrieve feed information for a user.
 * @param displayName unencoded friend display name
 * @param url unencoded url
 * @param readCipher function that generates a decrypting cipher to read the friend's publications.
 * @param rotCipher function that generates a descrypting cipher to read the friend's rotation messages.
 */
class Friend private constructor(val displayName: String, val url: String, private val readCipher: () -> Cipher?, private val rotCipher: (Int) -> Cipher?){

    /**
     * Take raw encoded feed information and decrypt it.
     * @param feed encoded feed information for this friend.
     */
    fun decryptFeed(feed: String): String {
        return CliqueConfig.encodedStringToString(feed, readCipher.invoke()!!)
    }

    /**
     * Take raw encoded rotation information and decrypt it.
     * @param rotation encoded rotation information from this friend.
     */
    fun decryptRotation(rotation: String) : String {
        return  CliqueConfig.encodedStringToString(rotation, rotCipher.invoke(Cipher.DECRYPT_MODE)!!)
    }

    /**
     * Take raw unencoded information and encrypt it using the shared rotation secret.
     * @param rotation unencoded rotation information to be encoded.
     */
    fun encryptRotation(rotation: String) : String {
        return CliqueConfig.stringToEncodedString(rotation, rotCipher.invoke(Cipher.ENCRYPT_MODE)!!)
    }

    companion object {
        /**
         * @param subscription user symmetric encrypted subscription information for the friend.
         * @param symDecrypt function that generates a decryption cipher for the exchange encryption used to encrypt the Subscription.
         */
        internal fun fromSubscription(subscription: CliqueSubscription, symCipher: (Int) -> Cipher?): Friend {
            // To create this friend we need to get the display name, url, and read key and turn them
            // into something we can use: A display name, url, and function that creates a read cipher for
            // the url.
            return Friend(
                    CliqueConfig.encodedStringToString(subscription.subscriber, symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                    CliqueConfig.encodedStringToString(subscription.subscription, symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                    fun() : Cipher? {
                        return cliqueKeyToAsymPrivateCipher(subscription.feedReadKey, Cipher.DECRYPT_MODE, symCipher)
                    },
                    fun(mode: Int) : Cipher? {
                        return cliqueKeyToSymCipher(subscription.rotateKey, mode, symCipher)
                    }
            )
        }
    }
}

/**
 * Rotation is a class that provides a way to generate the information necessary to create a
 * key rotation message when a new key is provided.
 * @param rotate a function that takes a new clique key name, a new url (both encoded), and a (this) Rotation and generates rotation information
 * for the given user, placing it into this Rotation.
 */
//class Rotation private constructor(val name: String, private val rotate: (String, String, Rotation) -> Unit) {
//
//    private var _key: String? = null
//    internal val key: String?
//        get() = _key
//
//    private var _url: String? = null
//    internal val url: String?
//        get() = _url
//
//    private var _cipher: String? = null
//    internal val cipher: String?
//        get() = _cipher
//
//    /**
//     * Sets up this rotation objection for the given user off the provided publish key name and url
//     * @param newKey the user symmetric encrypted name of the new publish key.
//     * @param newUrl the user symmetric encrypted url used to publish.
//     */
//    internal fun initialize(newKey: String, newUrl: String) {
//        rotate.invoke(newKey, newUrl, this)
//    }
//
//    companion object {
//        /**
//         * This produces a Rotation object that will create a RotationMessage when "rotateMessageForKey" is
//         * called and a new clique key name is provided (the assumption being that the key has already
//         * been created).
//         */
//        internal fun fromRotationDescription(description: CliqueRotateDescription, symCipher: (Int) -> Cipher?): Rotation {
//            val name = CliqueConfig.encodedStringToString(description.subscriber, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
//
//            val rotate = fun(keyName: String, encodedUrl: String, rotation: Rotation) {
//                return SecureDatabase.instance?.keyDao()?.findKey(keyName)?.let { newKey ->
//                    val transcode = fun (value: String): String =
//                            CliqueConfig.transcodeString(
//                                    value,
//                                    symCipher.invoke(Cipher.DECRYPT_MODE)!!,
//                                    cliqueKeyToAsymPrivateCipher(description.rotateKey, Cipher.ENCRYPT_MODE, symCipher)!!
//                            )
//
//                    rotation._cipher = transcode(newKey.cipher)
//                    rotation._key = transcode(newKey.key)
//                    rotation._url = transcode(encodedUrl)
//                }!!
//            }
//
//            return Rotation(name, rotate)
//        }
//    }
//}