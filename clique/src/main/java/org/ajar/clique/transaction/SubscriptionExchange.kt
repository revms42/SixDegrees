package org.ajar.clique.transaction

import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.AsymmetricEncryption
import org.ajar.clique.encryption.AsymmetricEncryptionDesc
import org.ajar.clique.facade.User
import javax.crypto.Cipher

/**
 * If you're sending an invitation to someone you send them your public one.
 * You make up a key pair and store the public half in the account object you create for them under public two.
 * You send the other half to them to become their Private One for the object they create for you.
 *
 * They then create a key pair, and send you the private half to put into the private one field for their account object on your side.
 * They keep the public half of the key pair and put it in their public two field for your account on their side.
 *
 * @property url this user's publish url
 * @property readKey this user's public read key for the url
 * @property readAlgo the algo used by the read key
 * @property rotateKey a freshly created asymmetric private key for the recipient to use to publish their rotate requests to you
 * @property rotateAlgo the algo used by the rotate key
 */
interface Invitation {
    val url: String
    val readKey: String
    val readAlgo: String
    val rotateKey: String
    val rotateAlgo: String
}

private data class InvitationData(
        override val url: String,
        override val readKey: String,
        override val readAlgo: String,
        override val rotateKey: String,
        override val rotateAlgo: String
) : Invitation

class SubscriptionExchange private constructor(private val user: User, private val exchangeCipher: (Int) -> Cipher?) {

    private data class KeyInfo(val desc: String, val key: String)

    internal data class FriendInfo(
            var name: String? = null,
            var url: String? = null,
            var rotateWriteKey: String? = null, // Publish a rotate message to the subscriber
            var rotateWriteAlgo: String? = null,
            var readKey: String? = null, // Read the subscriber's feed
            var readAlgo: String? = null,
            var rotateReadKey: String? = null, // Read a rotate message published by the subscriber
            var rotateReadAlgo: String? = null
    ) {
        val ready: Boolean
            get() {
                return listOf(name, url, readKey, readAlgo, rotateReadKey, rotateReadAlgo, rotateWriteKey, rotateWriteAlgo).none { it == null }
            }
    }

    internal val friendInfo: FriendInfo = FriendInfo()

    fun createInvitation(friendName: String, rotationKeyPairEncryption: AsymmetricEncryption = AsymmetricEncryptionDesc.DEFAULT) : Invitation? {
        return user.invitationInfo.invoke()?.let { invitationInfo ->
            // Transcode your read key and algo for the invitation.
            val transcodedReadInfo = SecureDatabase.instance?.keyDao()?.findKey(invitationInfo.feedReadKey)?.let { readCliqueKey ->
                val keyAlgoDesc = CliqueConfig.transcodeString(readCliqueKey.cipher, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                val key =  CliqueConfig.transcodeString(readCliqueKey.key, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                KeyInfo(keyAlgoDesc, key)
            }

            // Transcode your url for the invitation.
            val transcodedUrl = CliqueConfig.transcodeString(invitationInfo.subscription, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)

            // Generate a rotation key: The part you will keep will be to publish a rotate message to the subscriber. That part you send will
            // be the part that will enable them to read the message.
            rotationKeyPairEncryption.generateKeyPair(friendName).let { pair ->
                val encryptedCipherInfo = CliqueConfig.stringToEncodedString(rotationKeyPairEncryption.toString(), user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)

                friendInfo.name = CliqueConfig.stringToEncodedString(friendName, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                friendInfo.rotateWriteKey = CliqueConfig.byteArrayToEncodedString(pair.public.encoded, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                friendInfo.rotateWriteAlgo = encryptedCipherInfo

                val exchangeRotateCipherInfo = CliqueConfig.stringToEncodedString(rotationKeyPairEncryption.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)

                return InvitationData(
                        transcodedUrl,
                        transcodedReadInfo!!.key,
                        transcodedReadInfo.desc,
                        CliqueConfig.byteArrayToEncodedString(pair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!),
                        exchangeRotateCipherInfo
                )
            }
        }
    }

    fun readInvitation(invitation: Invitation) {
        friendInfo.readKey = CliqueConfig.transcodeString(invitation.readKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.readAlgo = CliqueConfig.transcodeString(invitation.readAlgo, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.url = CliqueConfig.transcodeString(invitation.url, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.rotateReadKey = CliqueConfig.transcodeString(invitation.rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.rotateReadAlgo = CliqueConfig.transcodeString(invitation.rotateAlgo, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
    }

    fun finalizeExchange() {
        if(friendInfo.ready) {
            user.addFriend(friendInfo)
        } else {
            throw NullPointerException("Friend Info is incomplete!")
        }
    }

    companion object {
        fun createExchange(user: User, exchangeCipher: (Int) -> Cipher) : SubscriptionExchange {
            return SubscriptionExchange(user, exchangeCipher)
        }
    }
}