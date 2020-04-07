package org.ajar.clique.transaction

import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
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
 * @param url this user's publish url
 * @param readKey this user's public read key for the url
 * @param readAlgo the algo used by the read key
 * @param rotateKey a freshly created asymmetric private key for the recipient to use to publish their rotate requests to you
 * @param rotateAlgo the algo used by the rotate key
 */

data class Invitation(val url: String, val readKey: String, val readAlgo: String, val rotateKey: String, val rotateAlgo: String)

class SubscriptionExchange private constructor(private val user: User, private val exchangeCipher: (Int) -> Cipher?) {

    private data class KeyInfo(val desc: String, val key: String)

    internal data class FriendInfo(
            var name: String? = null,
            var url: String? = null,
            var readKey: String? = null,
            var readAlgo: String? = null,
            var publicTwo: String? = null,
            var publicTwoAlgo: String? = null,
            var privateOne: String? = null,
            var privateOneAlgo: String? = null
    ) {
        val ready = listOf(name, url, readKey, readAlgo, publicTwo, publicTwoAlgo, privateOne, privateOneAlgo).none { it == null }
    }

    private val friendInfo: FriendInfo = FriendInfo()

    fun createInvitation(friendName: String, asymDescription: AsymmetricEncryptionDescription = CliqueConfig.assymetricEncryption) : Invitation? {
        return user.invitationInfo.invoke()?.let { invitationInfo ->
            val transcodedReadInfo = SecureDatabase.instance?.keyDao()?.findKey(invitationInfo.feedReadKey)?.let { readCliqueKey ->
                val keyAlgoDesc = CliqueConfig.transcodeString(readCliqueKey.cipher, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                val key =  CliqueConfig.transcodeString(readCliqueKey.key, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                KeyInfo(keyAlgoDesc, key)
            }

            val transcodedUrl = CliqueConfig.transcodeString(invitationInfo.subscription, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)

            CliqueConfig.createKeyPair(friendName, asymDescription).let { pair ->
                val encryptedCipherInfo = CliqueConfig.stringToEncodedString(asymDescription.toString(), user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)

                friendInfo.name = CliqueConfig.stringToEncodedString(friendName, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                friendInfo.publicTwo = CliqueConfig.byteArrayToEncodedString(pair.public.encoded, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                friendInfo.publicTwoAlgo = encryptedCipherInfo

                return Invitation(
                        transcodedUrl,
                        transcodedReadInfo!!.key,
                        transcodedReadInfo.desc,
                        CliqueConfig.byteArrayToEncodedString(pair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!),
                        encryptedCipherInfo
                )
            }
        }
    }

    fun readInvitation(invitation: Invitation) {
        friendInfo.readKey = CliqueConfig.transcodeString(invitation.readKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.readAlgo = CliqueConfig.transcodeString(invitation.readAlgo, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.url = CliqueConfig.transcodeString(invitation.url, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.privateOne = CliqueConfig.transcodeString(invitation.rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.privateOneAlgo = CliqueConfig.transcodeString(invitation.rotateAlgo, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
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