package org.ajar.clique.facade

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.Transformations
import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.*
import org.ajar.clique.encryption.*
import org.ajar.clique.transaction.SubscriptionExchange
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
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

private fun cliqueKeyToAsymPublicCipher(name: String, mode: Int, symCipher: (Int) -> Cipher?): Cipher? {
    return SecureDatabase.instance?.keyDao()?.findKey(name)?.let {
        val desc = AsymmetricEncryptionDesc.fromString(
                CliqueConfig.encodedStringToString(it.cipher, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
        )
        CipherProvider.Public(desc).cipher(
                mode,
                desc.publicKeyFromBytes(
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

private fun writeFeedMessage(userName: String, message: String, symCipher: (Int) -> Cipher?): String? {
    return SecureDatabase.instance?.accountDao()?.findPublishKey(userName)?.let {
        return CliqueConfig.stringToEncodedString(message,
                cliqueKeyToAsymPublicCipher(it, Cipher.ENCRYPT_MODE, symCipher)!!
        )
    }
}

private fun signEncodedMessage(userName: String, message: String, symCipher: (Int) -> Cipher?): String? {
    return SecureDatabase.instance?.accountDao()?.findSignatureKey(userName)?.let { keyRoot ->
        val root = CliqueConfig.encodedStringToString(keyRoot, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
        val keyName = sigRootToSigningKeyName(root)

        return SecureDatabase.instance?.keyDao()?.findKey(keyName)?.let { cliqueKey ->
            val desc = AsymmetricEncryptionDesc.fromString(
                    CliqueConfig.encodedStringToString(cliqueKey.cipher, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
            )

            val privateKey = desc.privateKeyFromBytes(
                    CliqueConfig.encodedStringToByteArray(cliqueKey.key, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
            )

             CliqueConfig.signatureForString(message, privateKey, desc)
        }
    }
}

private fun verifyEncodedMessage(keyName: String, message: String, signature: String, symCipher: (Int) -> Cipher?): Boolean? {
    return SecureDatabase.instance?.keyDao()?.findKey(keyName)?.let { cliqueKey ->
        val desc = AsymmetricEncryptionDesc.fromString(
                CliqueConfig.encodedStringToString(cliqueKey.cipher, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
        )

        val publicKey = desc.publicKeyFromBytes(
                CliqueConfig.encodedStringToByteArray(cliqueKey.key, symCipher.invoke(Cipher.DECRYPT_MODE)!!)
        )

        CliqueConfig.verifySignature(message, signature, publicKey, desc)
    }
}

internal fun userNameToSigningKeyName(userName: String): String = sigRootToSigningKeyName("$userName:sig")
internal fun sigRootToSigningKeyName(sigRoot: String): String = "$sigRoot(private)"
internal fun userNameToVerifyKeyName(userName: String): String = sigRootToVerifyKeyName("$userName:sig")
internal fun sigRootToVerifyKeyName(sigRoot: String): String = "$sigRoot(public)"

/**
 * Representation of the user of the current account.
 * @param name unencrypted user name associated with the AndroidKeyStore's RSA key used to encrypt the user's data.
 * @param filter the user name encrypted with the user's symmetric encryption, used to filter friends from the database.
 * @param url the unencrypted publication url of this user.
 * @param invitationInfo a CliqueSubscription which represents a portion of the information needed to create an invitation.
 * @param symCipher a function that will initialize a cipher to encrypt or decrypt the user's symmetric key encryption.
 * @param feed a function that encrypts the given plain-text into a string using this user's asymmetric publish key.
 * @param sign a function that produces a signature for a given message input.
 * @param androidKeyStoreUserCipher a function that generates a cipher using the user's specified android key store key
 * @param accountName the encrypted name of this user account (in the database)
 */
class User private constructor(
        val name: String,
        val url: String,
        internal val filter: String,
        internal val invitationInfo: () -> CliqueSubscription?,
        internal val symCipher: (Int) -> Cipher?,
        private val feed: (value: String) -> String?,
        private val sign: (value: String) -> String?,
        private val androidKeyStoreUserCipher: (Int) -> Cipher?,
        private val accountName: String
){
    fun writeFeedMessage(message: String): String? = feed(message)

    fun signMessage(message: String): String? = sign(message)

    val verifyKeyName: String
        get() = CliqueConfig.stringToEncodedString(userNameToVerifyKeyName(name), symCipher(Cipher.ENCRYPT_MODE)!!)

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

    internal fun getAccount() : CliqueAccount? {
        return SecureDatabase.instance?.accountDao()?.findAccount(accountName)
    }

    internal fun addFriend(friendInfo: SubscriptionExchange.FriendInfo) {
        val friendName = CliqueConfig.encodedStringToString(friendInfo.name, symCipher.invoke(Cipher.DECRYPT_MODE)!!)

        val appendTo = fun(append: String): String {
            return CliqueConfig.stringToEncodedString("$friendName:$append", symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        }

        val rotateKey = appendTo("key1")
        val feedReadKey = appendTo("key2")
        val verifyKey = appendTo("key3")

        //TODO("Make this work with the new friend info")
        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(rotateKey, friendInfo.rotateKey, friendInfo.rotateKeyAlgo))
        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(feedReadKey, friendInfo.friendReadKey, friendInfo.friendReadAlgo))
        SecureDatabase.instance?.keyDao()?.addKey(CliqueKey(verifyKey, friendInfo.friendSignKey, friendInfo.friendReadAlgo))

        val dbName = CliqueConfig.stringToEncodedString(friendName, androidKeyStoreUserCipher.invoke(Cipher.ENCRYPT_MODE)!!)

        val symKey = SecureDatabase.instance?.accountDao()?.findSymmetricDesc(accountName)

        SecureDatabase.instance?.accountDao()?.addAccount(CliqueAccount(
                dbName,
                friendInfo.name,
                filter,
                rotateKey,
                feedReadKey,
                verifyKey,
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

                    val signingKey = CliqueConfig.stringToEncodedString(userNameToSigningKeyName(user), symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                    val signer = fun(value: String): String? { return signEncodedMessage(signingKey, value, symCipher) }

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
                            signer,
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

                val sigKeyPair = generateUserSigningKeys(user, encryption, encryptSymKey)

                if(SecureDatabase.instance == null) SecureDatabase.init(context, CliqueConfig.dbName)

                val cliqueAccount = CliqueAccount(
                        encodedUser,
                        encDisplayName,
                        filter,
                        feedKeyPair.feedPublic,
                        feedKeyPair.feedPrivate,
                        sigKeyPair.sigRoot,
                        encryptSym,
                        encryptSymAlgo,
                        encUrl
                )
                SecureDatabase.instance!!.accountDao().addAccount(cliqueAccount)

                SecureDatabase.instance!!.keyDao().addKey(feedKeyPair.feedPublicKey)
                SecureDatabase.instance!!.keyDao().addKey(feedKeyPair.feedPrivateKey)
                SecureDatabase.instance!!.keyDao().addKey(sigKeyPair.sigPublicKey)
                SecureDatabase.instance!!.keyDao().addKey(sigKeyPair.sigPrivateKey)
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

        private fun generateUserSigningKeys(user: String, encryption: AsymmetricEncryption, encryptSymKey: () -> Cipher): SigKeyPair {
            val encryptionOne = "$user:sig"
            val encryptOnePair = encryption.generateKeyPair(encryptionOne, purpose = VERIFICATION_PURPOSE)

            val algoDescEncrypted = CliqueConfig.stringToEncodedString(encryption.toString(), encryptSymKey.invoke())

            val encryptOnePublic = CliqueConfig.byteArrayToEncodedString(encryptOnePair.public.encoded, encryptSymKey.invoke())
            val sigPublic = CliqueConfig.stringToEncodedString("$encryptionOne(public)", encryptSymKey.invoke())
            val sigPublicKey = CliqueKey(sigPublic, encryptOnePublic, algoDescEncrypted)

            val encryptOnePrivate = CliqueConfig.byteArrayToEncodedString(encryptOnePair.private.encoded, encryptSymKey.invoke())
            val sigPrivate = CliqueConfig.stringToEncodedString("$encryptionOne(private)", encryptSymKey.invoke())
            val sigPrivateKey = CliqueKey(sigPrivate, encryptOnePrivate, algoDescEncrypted)

            val sigRoot = CliqueConfig.stringToEncodedString(encryptionOne, encryptSymKey.invoke())

            return SigKeyPair(sigRoot, sigPublicKey, sigPrivateKey)
        }
    }
}

data class FeedKeyPair(val feedPublic: String, val feedPublicKey: CliqueKey, val feedPrivate: String, val feedPrivateKey: CliqueKey)
data class SigKeyPair(val sigRoot: String, val sigPublicKey: CliqueKey, val sigPrivateKey: CliqueKey)

/**
 * This is a representation of a subscription that is used to retrieve feed information for a user.
 * @param displayName unencoded friend display name
 * @param url unencoded url
 * @param readCipher function that generates a decrypting cipher to read the friend's publications.
 * @param rotCipher function that generates a descrypting cipher to read the friend's rotation messages.
 */
class Friend private constructor(
        val displayName: String,
        val url: String,
        private val readCipher: () -> Cipher?,
        private val verifyMessage: (message: String, signature: String) -> Boolean?,
        private val rotCipher: (Int) -> Cipher?
){

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
    fun decryptStringRotation(rotation: String) : String {
        return  CliqueConfig.encodedStringToString(rotation, rotCipher.invoke(Cipher.DECRYPT_MODE)!!)
    }

    /**
     * Take raw encoded rotation information and decrypt it to a byte array.
     * @param rotation encoded rotation information from this friend.
     */
    fun decryptByteArrayRotation(rotation: String) : ByteArray {
        return  CliqueConfig.encodedStringToByteArray(rotation, rotCipher.invoke(Cipher.DECRYPT_MODE)!!)
    }

    /**
     * Take raw unencoded information and encrypt it using the shared rotation secret.
     * @param rotation unencoded rotation information to be encoded.
     */
    fun encryptRotation(rotation: String) : String {
        return CliqueConfig.stringToEncodedString(rotation, rotCipher.invoke(Cipher.ENCRYPT_MODE)!!)
    }

    /**
     * Verify that the given message and signature match for this friend.
     * @param message the message to check.
     * @param signature the signature provided.
     */
    fun verifySignature(message: String, signature: String) : Boolean = verifyMessage(message, signature) == true

    /**
     * Create a rotation message that specifies the new values in the give user to the subscriber
     * (i.e. this Friend)
     * @param user the user initiating rotation
     * @return a rotation that contains the user's information encoded in this friend's rotation encryption
     */
    fun createRotationMessage(user: User) : Rotation {
        val subscription = user.invitationInfo.invoke()!!

        val cliqueKey = SecureDatabase.instance!!.keyDao().findKey(subscription.feedReadKey)!!

        return Rotation(
                CliqueConfig.encodedStringToByteArray(cliqueKey.key, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                CliqueConfig.encodedStringToString(cliqueKey.cipher, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!),
                CliqueConfig.encodedStringToString(subscription.subscription, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!)
        ).encrypt(rotCipher)
    }

    /**
     * Reads a Rotation in for this Friend and applies the new values to their account for the given
     * User.
     * @param user this User associated with this Friend
     * @param rotation the Rotation being sent for this Friend's account.
     */
    fun readRotationMessage(user: User, rotation: Rotation) {
        val transcode = fun(value: String) : String {
            return CliqueConfig.transcodeString(value, rotCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        }

        val newKey = rotation.encodedKey?.let { transcode(it) }
        val newCipher = rotation.cipher?.let { transcode(it) }
        val newUrl = rotation.cipher?.let { transcode(it) }

        toAccount(this, user.symCipher)?.also { subscription ->
            newUrl?.also { url -> subscription.url = url }

            val subKey = SecureDatabase.instance?.keyDao()?.findKey(subscription.key1)?.also { key ->
                newKey?.also { key.key = it }
                newCipher?.also { key.cipher = it }
            }

            subKey?.also { SecureDatabase.instance?.keyDao()?.updateKey(it) }
            SecureDatabase.instance?.accountDao()?.updateAccounts(subscription)
        }
    }

    companion object {
        /**
         * @param subscription user symmetric encrypted subscription information for the friend.
         * @param symCipher function that generates a decryption cipher for the exchange encryption used to encrypt the Subscription.
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
                    fun(message: String, signature: String) : Boolean? {
                        return verifyEncodedMessage(subscription.verifyKey, message, signature, symCipher)
                    },
                    fun(mode: Int) : Cipher? {
                        return cliqueKeyToSymCipher(subscription.rotateKey, mode, symCipher)
                    }
            )
        }

        /**
         * @param friend the Friend whose CliqueAccount you want
         * @param symCipher the cipher function to use to decrypt the CliqueAccount
         */
        internal fun toAccount(friend: Friend, symCipher: (Int) -> Cipher?): CliqueAccount? {
            return SecureDatabase.instance?.accountDao()?.findAccountByDisplayName(
                    CliqueConfig.stringToEncodedString(friend.displayName, symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
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
class Rotation(newKey: ByteArray? = null, newCipher: String? = null, newUrl: String? = null) {
    private var _encrypted = false
    val encrypted: Boolean
        get() = _encrypted

    private var _key = newKey
    var encodedKey: String? = null
    val key: ByteArray?
        get() = _key
    private var _cipher = newCipher
    val cipher: String?
        get() = _cipher
    private var _url = newUrl
    val url: String?
        get() = _url

    fun encrypt(encrypt: (Int) -> Cipher?): Rotation {
        if(!encrypted) {
            key?.also {
                encodedKey = CliqueConfig.byteArrayToEncodedString(it, encrypt.invoke(Cipher.ENCRYPT_MODE)!!)
            }
            cipher?.also {
                _cipher = CliqueConfig.stringToEncodedString(it, encrypt.invoke(Cipher.ENCRYPT_MODE)!!)
            }
            url?.also {
                _url = CliqueConfig.stringToEncodedString(it, encrypt.invoke(Cipher.ENCRYPT_MODE)!!)
            }
            _encrypted = true
        }
        return this
    }
}