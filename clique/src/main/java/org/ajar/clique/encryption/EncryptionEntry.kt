package org.ajar.clique.encryption

import android.security.keystore.KeyProperties
import org.conscrypt.Conscrypt
import java.lang.Exception
import java.security.KeyPairGenerator
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

class AlgorithmDesc private constructor(val name: String) {

    val ciphers = ArrayList<CipherDesc>()
    val keyGenerators = ArrayList<GeneratorDesc>()
    val keyPairGenerators = ArrayList<GeneratorDesc>()
    val factories = ArrayList<FactoryDesc>()

    override fun toString(): String {
        return "$name:\n \tCiphers: $ciphers\n\tKeyGenerators: $keyGenerators\n\tKeyPairGenerators: $keyPairGenerators\n\tKeyFactories: $factories"
    }

    companion object {
        private val all = HashMap<String, AlgorithmDesc>()
        val loaded : Collection<AlgorithmDesc>
            get() = all.values
        // A list of algorithms we could use to encode posted messages.
        val keyPairAlgorithms : Collection<AlgorithmDesc>
            get() = loaded.filter { desc ->
                    desc.keyPairGenerators.isNotEmpty() and desc.ciphers.isNotEmpty() and desc.factories.isNotEmpty()
                }
        // A list of algorithms we could use to encode our data locally in the db.
        val secretKeyAlgorithms : Collection<AlgorithmDesc>
            get() = loaded.filter { desc ->
                desc.keyGenerators.isNotEmpty() and desc.ciphers.isNotEmpty()
            }
        // A list of algorithms we could read if someone sent us a key (asymmetric assumed)
        val readableAlgorithms : Collection<AlgorithmDesc>
            get() = loaded.filter { desc ->
                desc.ciphers.isNotEmpty() and desc.factories.isNotEmpty()
            }
        // A list of algorithms that don't have ciphers but can read and write keys.
        val keyExchangeAlgorithms : Collection<AlgorithmDesc>
            get() = loaded.filter { desc ->
                desc.keyPairGenerators.isNotEmpty() and desc.factories.isNotEmpty()
            }

        fun toAlgorithm(name: String) : AlgorithmDesc {
            if(!all.contains(name)) {
                all[name] = AlgorithmDesc(name)
            }
            return all[name]!!
        }

        fun findAlgorithm(name: String) : AlgorithmDesc? {
            return all[name]
        }

        fun isSupportedForRead(description: String): Boolean {
            val algo = description.split("/")[0] // Just the algorithm
            return readableAlgorithms.firstOrNull { it.name == algo } != null
        }

        fun isSupportedForWrite(description: String): Boolean {
            val algoBlockPad = description.split("/")

            if(algoBlockPad.size >= 3) {
                val blockMode = BlockModeDesc.findBlockMode(algoBlockPad[1])
                val padding = PaddingDesc.findPadding(algoBlockPad[2])

                blockMode?.also { mode -> padding?.also { pad ->
                    var algoDesc = keyPairAlgorithms.firstOrNull { it.name == algoBlockPad[0] }
                    if(algoDesc != null) {
                        return areCipherParametersSupported(algoDesc, mode, pad)
                    }
                    algoDesc = secretKeyAlgorithms.firstOrNull { it.name == algoBlockPad[0] }
                    if(algoDesc != null) {
                        return areCipherParametersSupported(algoDesc, mode, pad)
                    }
                } }
            }

            return false
        }

        private fun areCipherParametersSupported(algoDesc: AlgorithmDesc, blockMode: BlockModeDesc, padding: PaddingDesc): Boolean {
            if(algoDesc.ciphers.isNotEmpty()) {
                return algoDesc.ciphers.firstOrNull { cipherDesc ->
                    cipherDesc.blockModes.contains(blockMode) && cipherDesc.paddings.contains(padding)
                } != null
            }
            return false
        }

        fun establishSupportedEncryption() {
            try {
                Security.addProvider(Conscrypt.newProvider())
            } catch (_: UnsatisfiedLinkError){}

            Security.getProviders().toList().forEach { provider ->
                val providerDesc = ProviderDesc.toProvider(provider.name)

                provider.services.forEach { service ->
                    val desc = AlgorithmDesc.toAlgorithm(service.algorithm)

                    when(service.type) {
                        "Cipher" -> {
                            val modes = service.getAttribute("SupportedModes")?.split("|")?.map { BlockModeDesc.toBlockMode(it) }?: ArrayList()
                            val paddings = service.getAttribute("SupportedPaddings")?.split("|")?.map { PaddingDesc.toPadding(it) }?: ArrayList()

                            desc.ciphers.add(CipherDesc(providerDesc, modes, paddings))
                        }
                        "KeyGenerator" -> {
                            val keySizes = service.getAttribute("KeySize")?.split("|")?.map { it.toInt() }?.toMutableList()?: ArrayList()
                            if(keySizes.isEmpty()) {
                                val generator = KeyGenerator.getInstance(desc.name)
                                val max = Cipher.getMaxAllowedKeyLength(desc.name)
                                val sequence = generateSequence(0) { if(it < 4096) it + 1 else null }

                                sequence.forEach {
                                    try {
                                        generator.init(it)
                                        keySizes.add(it)
                                    } catch (_: Exception) {}
                                }
                            }
                            desc.keyGenerators.add(GeneratorDesc(providerDesc, keySizes))
                        }
                        "KeyPairGenerator" -> {
                            val keySizes = service.getAttribute("KeySize")?.split("|")?.map { it.toInt() }?.toMutableList()?: ArrayList()
                            if(keySizes.isEmpty() || keySizes.size == 1) {
                                val generator = KeyPairGenerator.getInstance(desc.name)

                                val sequence = generateSequence(40) { if(it < 1024) it + 8 else null }

                                sequence.filter {
                                    try {
                                        generator.initialize(it)
                                        true
                                    } catch (_: Exception) { false }
                                }.firstOrNull {
                                    keySizes.add(it)
                                }
                            }

                            desc.keyPairGenerators.add(GeneratorDesc(providerDesc, keySizes))
                        }
                        "KeyFactory", "SecretKeyFactory"-> {
                            desc.factories.add(FactoryDesc(providerDesc))
                        }
                        "SecureRandom" -> {
                            SecureRandomDesc.toSecureRandom(service.algorithm, providerDesc)
                        }
                        "KeyStore" -> {
                            KeyStoreDesc.toKeyStore(service.algorithm, providerDesc)
                        }
                        "KeyAgreement" -> {
                            KeyAgreementDesc.toKeyAgreement(service.algorithm, providerDesc)
                        }
                        "AlgorithmParameters" -> {
                            if(service.algorithm == "EC") {
                                service.getAttribute("SupportedCurves").split("|").forEach { curveDesc ->
                                    curveDesc.replace("[\\[\\]]","").split(",").forEach { curve ->
                                        GeneratorParameterDesc.toParameterDesc(curve, providerDesc)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

data class CipherDesc(val provider: ProviderDesc, val blockModes: List<BlockModeDesc>, val paddings: List<PaddingDesc>)
/**
 * @param keySizes for a key generator this is a list of available key sizes. For a key pair generator it's the minimum size.
 */
data class GeneratorDesc(val provider: ProviderDesc, val keySizes: List<Int>)
data class FactoryDesc(val provider: ProviderDesc)

@Suppress("DataClassPrivateConstructor")
data class PaddingDesc private constructor(val name: String) {

    override fun toString(): String {
        return "Padding($name)"
    }

    companion object {
        private val _all = HashMap<String, PaddingDesc>()
        val all: Collection<PaddingDesc> = _all.values

        init {
            toPadding(KeyProperties.ENCRYPTION_PADDING_NONE)
            toPadding(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            toPadding(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            toPadding(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            toPadding(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            toPadding(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        }

        fun toPadding(name: String) : PaddingDesc {
            if(!_all.contains(name)) {
                _all[name] = PaddingDesc(name)
            }
            return _all[name]!!
        }

        fun findPadding(name: String) : PaddingDesc? = _all[name]
    }
}

@Suppress("DataClassPrivateConstructor")
data class BlockModeDesc private constructor(val name: String) {

    override fun toString(): String {
        return "BlockMode($name)"
    }

    companion object {
        private val _all = HashMap<String, BlockModeDesc>()
        val all: Collection<BlockModeDesc> = _all.values

        init {
            toBlockMode(KeyProperties.BLOCK_MODE_GCM)
            toBlockMode(KeyProperties.BLOCK_MODE_CBC)
            toBlockMode(KeyProperties.BLOCK_MODE_CTR)
            toBlockMode(KeyProperties.BLOCK_MODE_ECB)
        }

        fun toBlockMode(name: String) : BlockModeDesc {
            if(!_all.contains(name)) {
                _all[name] = BlockModeDesc(name)
            }
            return _all[name]!!
        }

        fun findBlockMode(name: String): BlockModeDesc? = _all[name]
    }
}

@Suppress("DataClassPrivateConstructor")
data class ProviderDesc private constructor(val name: String) {

    override fun toString(): String {
        return "Provider($name)"
    }

    companion object {
        private val all = HashMap<String, ProviderDesc>()

        fun toProvider(name: String) : ProviderDesc {
            if(!all.contains(name)) {
                all[name] = ProviderDesc(name)
            }
            return all[name]!!
        }

        fun findProvider(name: String) : ProviderDesc? = all[name]
    }
}

@Suppress("DataClassPrivateConstructor")
data class SecureRandomDesc private constructor(val name: String, val provider: ProviderDesc) {

    companion object {
        private val _all = HashMap<String, SecureRandomDesc>()
        val all: Map<String, SecureRandomDesc> = _all

        fun toSecureRandom(name: String, provider: ProviderDesc) : SecureRandomDesc {
            if(!_all.contains(name)) {
                _all[name] = SecureRandomDesc(name, provider)
            }
            return _all[name]!!
        }

        fun findSecureRandom(name: String) : SecureRandomDesc? = _all[name]
    }
}

@Suppress("DataClassPrivateConstructor")
data class KeyStoreDesc private constructor(val name: String, val provider: ProviderDesc) {

    companion object {
        private val _all = HashMap<String, KeyStoreDesc>()
        val all: Map<String, KeyStoreDesc> = _all

        fun toKeyStore(name: String, provider: ProviderDesc) : KeyStoreDesc {
            if(!_all.contains(name)) {
                _all[name] = KeyStoreDesc(name, provider)
            }
            return _all[name]!!
        }

        fun findKeyStore(name: String) : KeyStoreDesc? = _all[name]
    }
}

@Suppress("DataClassPrivateConstructor")
data class KeyAgreementDesc private constructor(val name: String, val provider: ProviderDesc) {
    companion object {
        private val _all = HashMap<String, KeyAgreementDesc>()

        val all: Map<String, KeyAgreementDesc> = _all

        fun toKeyAgreement(name: String, provider: ProviderDesc) : KeyAgreementDesc {
            if(!_all.contains(name)) {
                _all[name] = KeyAgreementDesc(name, provider)
            }
            return _all[name]!!
        }

        fun findKeyAgreement(name: String): KeyAgreementDesc? = _all[name]
    }
}

@Suppress("DataClassPrivateConstructor")
data class GeneratorParameterDesc private constructor(val name: String, val provider: ProviderDesc) {

    companion object {
        private val _all = HashMap<String, GeneratorParameterDesc>()

        val all: Map<String, GeneratorParameterDesc> = _all

        fun toParameterDesc(name: String, provider: ProviderDesc) : GeneratorParameterDesc {
            if(!_all.contains(name)) {
                _all[name] = GeneratorParameterDesc(name, provider)
            }
            return _all[name]!!
        }

        fun findParameterDesc(name: String) : GeneratorParameterDesc? = _all[name]
    }
}