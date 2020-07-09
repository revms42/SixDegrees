package org.ajar.clique.transaction

import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.*
import org.ajar.clique.facade.User
import java.security.PrivateKey
import java.security.PublicKey
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
 * @property rotateKey a freshly created asymmetric private key for the recipient to generate a shared secret with
 * @property agreement the algo that both parties agree on for their created shared secret
 */
interface Invitation {
    val url: String
    val readKey: String
    val readAlgo: String
    val rotateKey: String
    val agreement: String
}

private data class InvitationData(
        override val url: String,
        override val readKey: String,
        override val readAlgo: String,
        override val rotateKey: String,
        override val agreement: String
) : Invitation

class SubscriptionExchange private constructor(private val user: User, private val exchangeCipher: (Int) -> Cipher?) {

    private data class KeyInfo(val desc: String, val key: String)

    internal data class FriendInfoAggregator(
            var name: String? = null, // Friends name, transcoded for subscription creation
            var url: String? = null, // Friends url, transcoded for subscription creation
            var friendReadKey: String? = null, // Friend's key (private), transcoded for CliqueKey creation
            var friendReadAlgo: String? = null, // Friend's read key algo, transcoded for CliqueKey creation
            internal var friendRotateKey: PrivateKey? = null, // Friend's rotate key (private)
            internal var personalRotateKey: PublicKey? = null, // Personal rotate key (public)
            internal var agreement: SharedSecretExchange? = null
    ) {
        val ready: Boolean
            get() {
                return listOf(name, url, friendReadKey, friendReadAlgo).none { it == null }
                        && friendRotateKey != null
                        && personalRotateKey != null
                        && agreement != null
            }

        fun publishInfo(encode: (Int) -> Cipher?): FriendInfo? {
            return if(ready) {
                val secretKey = CliqueConfig.byteArrayToEncodedString(agreement!!.generateSecret(friendRotateKey!!).encoded, encode.invoke(Cipher.ENCRYPT_MODE)!!)
                val secretKeyAlgo = CliqueConfig.stringToEncodedString(agreement!!.secretAlgo.toString(), encode.invoke(Cipher.ENCRYPT_MODE)!!)

                return FriendInfo(name!!, url!!, friendReadKey!!, friendReadAlgo!!, secretKey, secretKeyAlgo)
            } else null
        }
    }

    data class FriendInfo(
            val name: String,
            val url: String,
            val friendReadKey: String,
            val friendReadAlgo: String,
            val rotateKey: String,
            val rotateKeyAlgo: String
    )

    internal val friendInfo: FriendInfoAggregator = FriendInfoAggregator()

    fun createInvitation(friendName: String, sharedSecret: SharedSecretExchange = SharedSecretExchangeDesc.DEFAULT) : Invitation? {
        return user.invitationInfo.invoke()?.let { invitationInfo ->
            // Transcode your read key and algo for the invitation.
            val transcodedReadInfo = SecureDatabase.instance?.keyDao()?.findKey(invitationInfo.feedReadKey)?.let { readCliqueKey ->
                val keyAlgoDesc = CliqueConfig.transcodeString(readCliqueKey.cipher, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                val key =  CliqueConfig.transcodeString(readCliqueKey.key, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                KeyInfo(keyAlgoDesc, key)
            }

            // Transcode your url for the invitation.
            val transcodedUrl = CliqueConfig.transcodeString(invitationInfo.subscription, user.symCipher.invoke(Cipher.DECRYPT_MODE)!!, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)

            val transcodedSharedSecretDesc = CliqueConfig.stringToEncodedString(sharedSecret.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)
            sharedSecret.generateKeyPair().let { pair ->
                val encodedKey = CliqueConfig.byteArrayToEncodedString(pair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)!!)

                friendInfo.name = CliqueConfig.stringToEncodedString(friendName, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                friendInfo.personalRotateKey = pair.public
                friendInfo.agreement = sharedSecret

                return InvitationData(
                        transcodedUrl,
                        transcodedReadInfo!!.key,
                        transcodedReadInfo.desc,
                        encodedKey,
                        transcodedSharedSecretDesc
                )
            }
        }
    }

    fun readInvitation(invitation: Invitation) {
        friendInfo.friendReadKey = CliqueConfig.transcodeString(invitation.readKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.friendReadAlgo = CliqueConfig.transcodeString(invitation.readAlgo, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        friendInfo.url = CliqueConfig.transcodeString(invitation.url, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)

        if(friendInfo.agreement == null) friendInfo.agreement = SharedSecretExchangeDesc.fromString(CliqueConfig.encodedStringToString(invitation.agreement, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!))

        val rotateKeyBytes = CliqueConfig.encodedStringToByteArray(invitation.rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)!!)
        friendInfo.friendRotateKey = friendInfo.agreement!!.privateKeyFromBytes(rotateKeyBytes)
    }

    fun finalizeExchange() {
        friendInfo.publishInfo(user.symCipher)?.let {
            user.addFriend(it)
            true
        }?: throw NullPointerException("Friend Info is incomplete!")
    }

    companion object {
        fun createExchange(user: User, exchangeCipher: (Int) -> Cipher) : SubscriptionExchange {
            return SubscriptionExchange(user, exchangeCipher)
        }
    }
}