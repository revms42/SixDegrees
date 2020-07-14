package org.ajar.clique.encryption

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.ajar.clique.encryption.Encryption.Companion.createSpecBuilder
import java.security.*
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

private const val ENCRYPTION_PURPOSE = KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT

interface Encryption {
    val algorithm: String
    val cipherGenerator: String
    val blockMode: String
    val keySize: Int
    val keyGenerator: String
    val padding: String

    var createKeyGenSpec: (name: String, purpose: Int) -> AlgorithmParameterSpec?

    companion object {
        internal var createSpecBuilder: (String, Int) -> KeyGenParameterSpec.Builder = KeyGenParameterSpec::Builder

        internal fun setKeySpecBuilder(specBuilder: (String, Int) -> KeyGenParameterSpec.Builder) {
            this.createSpecBuilder = specBuilder
        }

        internal var resolverProvider: (String) -> Provider? = Security::getProvider

        internal fun setProviderResolver(resolver: (String) -> Provider?) {
            this.resolverProvider = resolver
        }
    }
}

interface SharedSecretExchange {
    val algorithm: String
    val keyGenerator: String
    val keyAgreement: String
    val agreementProvider: String
    val generatorParameter: String
    val secretAlgo: SymmetricEncryption
    val secureRandom: String
    val randomProvider: String

    var createKeyGenSpec: (name: String) -> AlgorithmParameterSpec?

    fun generateKeyPair(): KeyPair
    fun generateSecret(key: PrivateKey): SecretKey
    fun generateSecret(key: PublicKey): SecretKey
    fun privateKeyFromBytes(keyBytes: ByteArray): PrivateKey
    fun publicKeyFromBytes(keyBytes: ByteArray): PublicKey
}

interface SymmetricEncryption : Encryption {
    val secureRandom: String
    val secureRandomProvider: String

    fun generateSecretKey(name: String = ""): SecretKey
    fun secretKeyFromBytes(byteArray: ByteArray) : SecretKey
}

interface AsymmetricEncryption : Encryption {
    val signaturePadding: String
    val factory: String

    fun generateKeyPair(name: String = "", keyStore: String? = null): KeyPair
    fun privateKeyFromBytes(keyBytes: ByteArray): PrivateKey
    fun publicKeyFromBytes(keyBytes: ByteArray): PublicKey
}

data class SymmetricEncryptionDesc(
        override val algorithm: String,
        override val cipherGenerator: String,
        override val blockMode: String,
        override val keySize: Int,
        override val secureRandom: String,
        override val keyGenerator: String,
        override val padding: String,
        override val secureRandomProvider: String
) : SymmetricEncryption {

    override fun toString(): String {
        return "$algorithm/$blockMode/$padding/$keySize/$secureRandom:$cipherGenerator/$keyGenerator/$secureRandomProvider"
    }

    override var createKeyGenSpec: (name: String, purpose: Int) -> AlgorithmParameterSpec? =
            fun(name, purpose): KeyGenParameterSpec {
                return createSpecBuilder.invoke(name, purpose)
                        .setKeySize(keySize)
                        .setBlockModes(blockMode)
                        .setEncryptionPaddings(padding)
                        .setRandomizedEncryptionRequired(true)
                        .build()
            }

    override fun generateSecretKey(name: String): SecretKey {
        val generator = createKeyGenerator.invoke(algorithm, Encryption.resolverProvider(keyGenerator))

        val secureRandom = createSecureRandom.invoke(secureRandom, Encryption.resolverProvider(secureRandomProvider))
        val spec = createKeyGenSpec(name, ENCRYPTION_PURPOSE)

        if(spec != null) {
            generator.init(spec, secureRandom)
        } else {
            // We wouldn't expect to find this in Android but it happens in unit tests.
            generator.init(keySize, secureRandom)
        }

        return generator.generateKey()
    }

    override fun secretKeyFromBytes(byteArray: ByteArray) : SecretKey {
        return SecretKeySpec(byteArray, algorithm)
    }

    companion object {
        val DEFAULT by lazy { EncryptionBuilder.symmetric().build() as SymmetricEncryption }

        private var createKeyGenerator: (String, Provider?) -> KeyGenerator = KeyGenerator::getInstance

        internal fun setKeyGeneratorCreator(keyGenerator: (String, Provider?) -> KeyGenerator) {
            this.createKeyGenerator = keyGenerator
        }

        private var createSecureRandom: (String, Provider?) -> SecureRandom = SecureRandom::getInstance

        internal fun setSecureRandomCreator(secureRandom: (String, Provider?) -> SecureRandom) {
            this.createSecureRandom = secureRandom
        }

        fun fromString(desc: String): SymmetricEncryptionDesc {
            val descProvider = desc.split(":")

            if(descProvider.size == 2) {
                val algoBlockPadSizeRand = descProvider[0].split("/")

                if(algoBlockPadSizeRand.size == 5) {
                    val cipherKeyRandom = descProvider[1].split("/")

                    if(cipherKeyRandom.size == 3) {
                        return SymmetricEncryptionDesc(
                                algoBlockPadSizeRand[0],
                                cipherKeyRandom[0],
                                algoBlockPadSizeRand[1],
                                algoBlockPadSizeRand[3].toInt(),
                                algoBlockPadSizeRand[4],
                                cipherKeyRandom[1],
                                algoBlockPadSizeRand[2],
                                cipherKeyRandom[2]
                        )
                    } else {
                        throw IllegalArgumentException("Provider block did not contain the correct number of entries: Wanted 3 and got ${cipherKeyRandom.size}")
                    }
                } else {
                    throw IllegalArgumentException("Description block did not contain the correct number of entries: Wanted 5 and got ${algoBlockPadSizeRand.spliterator()}")
                }
            } else {
                throw IllegalArgumentException("Description did not contain a description and a provider block!")
            }
        }
    }
}

data class AsymmetricEncryptionDesc(
        override val algorithm: String,
        override val cipherGenerator: String,
        override val blockMode: String,
        override val keySize: Int,
        override val keyGenerator: String,
        override val padding: String,
        override val signaturePadding: String,
        override val factory: String
) : AsymmetricEncryption {

    private var requireAuthentication = false

    override fun toString(): String {
        return "$algorithm/$blockMode/$padding/$signaturePadding/$keySize:$cipherGenerator/$keyGenerator/$factory"
    }

    override var createKeyGenSpec: (name: String, purpose: Int) -> AlgorithmParameterSpec? =
        fun(name, purpose): KeyGenParameterSpec {
            val builder = createSpecBuilder.invoke(name, purpose)
                    .setKeySize(keySize)
                    .setBlockModes(blockMode)
                    .setEncryptionPaddings(padding)
                    .setSignaturePaddings(signaturePadding)

            if(requireAuthentication) {
                builder.setUserAuthenticationRequired(true)
            }

            return builder.build()
        }

    override fun generateKeyPair(name: String, keyStore: String?): KeyPair {
        val keyPairGenerator = if(keyStore == null) {
            createKeyPairGenerator.invoke(algorithm, Encryption.resolverProvider(keyGenerator))
        } else {
            requireAuthentication = true
            createKeyPairGenerator.invoke(algorithm, Encryption.resolverProvider(keyStore))
        }

        keyPairGenerator.initialize(createKeyGenSpec(name, ENCRYPTION_PURPOSE))

        requireAuthentication = false
        return keyPairGenerator.generateKeyPair()
    }

    override fun privateKeyFromBytes(keyBytes: ByteArray): PrivateKey {
        //TODO: The algorithm argument here doesn't match the one we previously used
        val factory = createKeyFactory.invoke(algorithm, Encryption.resolverProvider(factory))
        return factory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    override fun publicKeyFromBytes(keyBytes: ByteArray): PublicKey {
        //TODO: The algorithm argument here doesn't match the one we previously used
        val factory = createKeyFactory.invoke(algorithm, Encryption.resolverProvider(factory))
        return factory.generatePublic(X509EncodedKeySpec(keyBytes))
    }

    companion object {
        val DEFAULT by lazy { EncryptionBuilder.asymetric().build() as AsymmetricEncryption }

        private var createKeyPairGenerator: (String, Provider?) -> KeyPairGenerator = KeyPairGenerator::getInstance

        internal fun setKeyPairGeneratorCreator(keyPairGenerator: (String, Provider?) -> KeyPairGenerator) {
            this.createKeyPairGenerator = keyPairGenerator
        }

        private var createKeyFactory: (String, Provider?) -> KeyFactory = KeyFactory::getInstance

        internal fun setKeyFactoryCreator(factoryCreator: (String, Provider?) -> KeyFactory) {
            this.createKeyFactory = factoryCreator
        }

        fun fromString(desc: String) : AsymmetricEncryption {
            val descProvider = desc.split(":")

            if(descProvider.size == 2) {
                val algoBlockPadSigSize = descProvider[0].split("/")

                if(algoBlockPadSigSize.size == 5) {
                    val cipherKeyFactory = descProvider[1].split("/")

                    if(cipherKeyFactory.size == 3) {
                        return AsymmetricEncryptionDesc(
                                algoBlockPadSigSize[0],
                                cipherKeyFactory[0],
                                algoBlockPadSigSize[1],
                                algoBlockPadSigSize[4].toInt(),
                                cipherKeyFactory[1],
                                algoBlockPadSigSize[2],
                                algoBlockPadSigSize[3],
                                cipherKeyFactory[2]
                        )
                    } else {
                        throw IllegalArgumentException("Provider block did not contain the correct number of entries: Wanted 3 and got ${cipherKeyFactory.size}")
                    }
                } else {
                    throw IllegalArgumentException("Description block did not contain the correct number of entries: Wanted 5 and got ${algoBlockPadSigSize.spliterator()}")
                }
            } else {
                throw IllegalArgumentException("Description did not contain a description and a provider block!")
            }
        }
    }
}

data class SharedSecretExchangeDesc(
        override val algorithm: String,
        override val keyGenerator: String,
        override val keyAgreement: String,
        override val agreementProvider: String,
        override val generatorParameter: String,
        override val secretAlgo: SymmetricEncryption,
        override val secureRandom: String,
        override val randomProvider: String
) : SharedSecretExchange {
    override var createKeyGenSpec: (name: String) -> AlgorithmParameterSpec? = ::ECGenParameterSpec

    override fun toString() : String {
        return "$algorithm,$keyGenerator,$keyAgreement,$agreementProvider,$generatorParameter,$secretAlgo,$secureRandom,$randomProvider"
    }

    override fun generateKeyPair(): KeyPair {
        val keyPairGenerator = createKeyPairGenerator.invoke(algorithm, Encryption.resolverProvider(keyGenerator))

        keyPairGenerator.initialize(createKeyGenSpec(generatorParameter))

        return keyPairGenerator.generateKeyPair()
    }

    override fun generateSecret(key: PrivateKey): SecretKey = generateSecret(generateKeyPair().public, key)

    override fun generateSecret(key: PublicKey): SecretKey = generateSecret(key, generateKeyPair().private)

    private fun generateSecret(public: PublicKey, privateKey: PrivateKey): SecretKey {
        val agreement = createKeyAgreement.invoke(keyAgreement, Encryption.resolverProvider(agreementProvider))

        // TODO: This seems better, but I can find no examples.
        // agreement.init(privateKey, params, random)
        val random = createSecureRandom.invoke(secureRandom, Encryption.resolverProvider(randomProvider))
        agreement.init(privateKey, random)

        agreement.doPhase(public, true)

        val bytes = agreement.generateSecret().let { rawArray ->
            // The rawArray is almost never the correct size for the given algo. So, size it appropriately
            when {
                rawArray.size > (secretAlgo.keySize/8) -> rawArray.slice(0 until (secretAlgo.keySize/8)).toByteArray()
                rawArray.size < (secretAlgo.keySize/8) -> {
                    val finishedBytes = rawArray.toCollection(ArrayList())

                    // TODO: I *don't* like this, but I need a predictable way to generate this.
                    while (finishedBytes.size < (secretAlgo.keySize/8)) finishedBytes.add(' '.toByte())

                    finishedBytes.toByteArray()
                }
                else -> rawArray
            }
        }

        // The secret key bytes are almost always larger than the bits required by the secret algorithm.
        return SecretKeySpec(bytes, secretAlgo.algorithm)
    }

    override fun privateKeyFromBytes(keyBytes: ByteArray): PrivateKey {
        //TODO: Not sure if the key generator is the same as the factory
        val factory = createKeyFactory.invoke(algorithm, Encryption.resolverProvider(keyGenerator))
        return factory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    override fun publicKeyFromBytes(keyBytes: ByteArray): PublicKey {
        //TODO: Not sure if the key generator is the same as the factory
        val factory = createKeyFactory.invoke(algorithm, Encryption.resolverProvider(keyGenerator))
        return factory.generatePublic(X509EncodedKeySpec(keyBytes))
    }

    companion object {
        val DEFAULT by lazy { SharedSecretBuilder.create().build(SymmetricEncryptionDesc.DEFAULT)!! }

        private var createKeyPairGenerator: (String, Provider?) -> KeyPairGenerator = KeyPairGenerator::getInstance

        internal fun setKeyPairGeneratorCreator(keyPairGenerator: (String, Provider?) -> KeyPairGenerator) {
            this.createKeyPairGenerator = keyPairGenerator
        }

        private var createKeyAgreement: (String, Provider?) -> KeyAgreement = KeyAgreement::getInstance

        internal fun setKeyAgreementCreator(keyAgreementCreator: (String, Provider?) -> KeyAgreement) {
            this.createKeyAgreement = keyAgreementCreator
        }

        private var createSecureRandom: (String, Provider?) -> SecureRandom = SecureRandom::getInstance

        internal fun setSecureRandomCreator(secureRandom: (String, Provider?) -> SecureRandom) {
            this.createSecureRandom = secureRandom
        }

        private var createKeyFactory: (String, Provider?) -> KeyFactory = KeyFactory::getInstance

        internal fun setKeyFactoryCreator(factoryCreator: (String, Provider?) -> KeyFactory) {
            this.createKeyFactory = factoryCreator
        }

        fun fromString(desc: String): SharedSecretExchangeDesc {
            val parts = desc.split(",")
            return SharedSecretExchangeDesc(
                    parts[0],
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    SymmetricEncryptionDesc.fromString(parts[5]),
                    parts[6],
                    parts[7]
            )
        }
    }
}

sealed class CipherProvider(private val desc: Encryption) {
    class Symmetric(desc: SymmetricEncryption) : CipherProvider(desc) {
        override val keyFromBytes: (ByteArray) -> Key = desc::secretKeyFromBytes
    }
    class Private(desc: AsymmetricEncryption) : CipherProvider(desc) {
        override val keyFromBytes: (ByteArray) -> Key = desc::privateKeyFromBytes
    }
    class Public(desc: AsymmetricEncryption) : CipherProvider(desc) {
        override val keyFromBytes: (ByteArray) -> Key = desc::publicKeyFromBytes
    }

    abstract val keyFromBytes: (ByteArray) -> Key

    fun cipher(mode: Int, keyBytes: ByteArray): Cipher {
        return cipher(mode, keyFromBytes.invoke(keyBytes))
    }

    fun cipher(mode: Int, key: Key): Cipher {
        //The algorithm we use here should match the way we used to do it....
        val cipher = Cipher.getInstance(
                "${desc.algorithm}/${desc.blockMode}/${desc.padding}",
                Encryption.resolverProvider(desc.cipherGenerator)
        )
        cipher.init(mode, key)
        return cipher
    }
}

class EncryptionBuilder private constructor(private val sym: Boolean) {

    private var algorithm: AlgorithmDesc? = null
    private var blockMode: BlockModeDesc? = null
    private var encryptionPadding: PaddingDesc? = null
    private var keySize: Int? = null
    private var signaturePadding: PaddingDesc? = null
    private var secureRandom: SecureRandomDesc? = null
    private var generatorProvider: GeneratorDesc? = null
    private var cipherProvider: CipherDesc? = null
    private var factoryProvider: FactoryDesc? = null

    fun listAlgorithms(): List<AlgorithmDesc> {
        return if(sym) {
            AlgorithmDesc.keyPairAlgorithms.toList()
        } else {
            AlgorithmDesc.secretKeyAlgorithms.toList()
        }
    }
    fun algorithm(algorithmDesc: AlgorithmDesc): EncryptionBuilder {
        this.algorithm = algorithmDesc
        return this
    }

    fun listCipherProviders(): List<CipherDesc> = algorithm!!.ciphers
    fun cipher(cipherDesc: CipherDesc) : EncryptionBuilder {
        cipherProvider = cipherDesc
        return this
    }

    fun listBlockModes(): List<BlockModeDesc> {
        return if(cipherProvider?.blockModes?.size?: -1 > 0) {
            cipherProvider!!.blockModes
        } else {
            BlockModeDesc.all.toList()
        }
    }
    fun blockMode(mode: BlockModeDesc): EncryptionBuilder {
        blockMode = mode
        return this
    }

    fun listPaddings(): List<PaddingDesc> {
        return if(cipherProvider?.paddings?.size?: -1 > 0) {
            cipherProvider!!.paddings
        } else {
            PaddingDesc.all.toList()
        }
    }
    fun encryptionPadding(pad: PaddingDesc): EncryptionBuilder {
        encryptionPadding = pad
        return this
    }
    fun signaturePadding(pad: PaddingDesc): EncryptionBuilder {
        signaturePadding = pad
        return this
    }

    fun listKeyGenerators(): List<GeneratorDesc> {
        return if(algorithm!!.keyGenerators.size > 0) {
            algorithm!!.keyGenerators
        } else {
            algorithm!!.keyPairGenerators
        }
    }
    fun keyGenerator(generator: GeneratorDesc): EncryptionBuilder {
        generatorProvider = generator
        return this
    }

    fun listKeyFactories(): List<FactoryDesc> = algorithm!!.factories
    fun keyFactory(factory: FactoryDesc): EncryptionBuilder {
        factoryProvider = factory
        return this
    }

    fun build(): Encryption {
        return if(sym) {
            SymmetricEncryptionDesc(
                    algorithm!!.name,
                    cipherProvider!!.provider.name,
                    blockMode!!.name,
                    keySize!!,
                    secureRandom!!.name,
                    generatorProvider!!.provider.name,
                    encryptionPadding!!.name,
                    secureRandom!!.provider.name
            )
        } else {
            AsymmetricEncryptionDesc(
                    algorithm!!.name,
                    cipherProvider!!.provider.name,
                    blockMode!!.name,
                    keySize!!,
                    generatorProvider!!.provider.name,
                    encryptionPadding!!.name,
                    signaturePadding!!.name,
                    factoryProvider!!.provider.name
            )
        }
    }

    companion object {

        private val isAndroid = System.getProperty("java.vendor")?.contains("Android")?: false

        fun asymetric() : EncryptionBuilder {
            if(AlgorithmDesc.loaded.isEmpty()) {
                AlgorithmDesc.establishSupportedEncryption()
            }

            val builder = EncryptionBuilder(false)

            if(isAndroid) {
                builder.encryptionPadding = PaddingDesc.findPadding(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                builder.blockMode = BlockModeDesc.findBlockMode(KeyProperties.BLOCK_MODE_GCM)
                builder.keySize = 4096
            } else {
                //Note: This is one of the *only* ciphers java requires that you implement
                builder.encryptionPadding = PaddingDesc.findPadding(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                builder.blockMode = BlockModeDesc.findBlockMode(KeyProperties.BLOCK_MODE_ECB)
                builder.keySize = 2048
            }
            builder.algorithm = AlgorithmDesc.toAlgorithm(KeyProperties.KEY_ALGORITHM_RSA)

            builder.signaturePadding = PaddingDesc.findPadding(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            builder.cipherProvider = builder.algorithm!!.ciphers.firstOrNull()
            builder.generatorProvider = builder.algorithm!!.keyPairGenerators.firstOrNull()
            builder.factoryProvider = builder.algorithm!!.factories.firstOrNull()

            return builder
        }

        fun symmetric() : EncryptionBuilder {
            if(AlgorithmDesc.loaded.isEmpty()) {
                AlgorithmDesc.establishSupportedEncryption()
            }

            val builder = EncryptionBuilder(true)

            if(isAndroid) {
                builder.encryptionPadding = PaddingDesc.findPadding(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                builder.blockMode = BlockModeDesc.findBlockMode(KeyProperties.BLOCK_MODE_GCM)
                builder.keySize = 256
            } else {
                //Note: This is one of the *only* paddings that java requires you implement.
                builder.encryptionPadding = PaddingDesc.toPadding("PKCS5Padding")
                builder.blockMode = BlockModeDesc.findBlockMode(KeyProperties.BLOCK_MODE_ECB)
                builder.keySize = 128
            }
            builder.algorithm = AlgorithmDesc.toAlgorithm(KeyProperties.KEY_ALGORITHM_AES)

            builder.secureRandom = SecureRandomDesc.findSecureRandom("SHA1PRNG")
            builder.cipherProvider = builder.algorithm!!.ciphers.firstOrNull()
            builder.generatorProvider = builder.algorithm!!.keyGenerators.firstOrNull()

            return builder
        }
    }
}

class SharedSecretBuilder private constructor() {
    private var algorithm: AlgorithmDesc? = null
    private var keyPairGenerator: GeneratorDesc? = null
    private var agreementProvider: KeyAgreementDesc? = null
    private var parameterDesc: GeneratorParameterDesc? = null
    private var secureRandomDesc: SecureRandomDesc? = null

    fun build(desc: SymmetricEncryption): SharedSecretExchange? {
        return SharedSecretExchangeDesc(
                algorithm!!.name,
                keyPairGenerator!!.provider.name,
                agreementProvider!!.name,
                agreementProvider!!.provider.name,
                parameterDesc!!.name,
                desc,
                secureRandomDesc?.name?: desc.secureRandom,
                secureRandomDesc?.provider?.name?: desc.secureRandomProvider
        )
    }

    fun listAlgorithms(): List<AlgorithmDesc> {
        return AlgorithmDesc.keyExchangeAlgorithms.toList()
    }
    fun algorithm(algo: AlgorithmDesc): SharedSecretBuilder {
        algorithm = algo
        return this
    }

    fun listKeyAgreements(): List<KeyAgreementDesc> {
        return KeyAgreementDesc.all.values.toList()
    }
    fun keyAgreement(provider: KeyAgreementDesc): SharedSecretBuilder {
        agreementProvider = provider
        return this
    }

    fun listParameterDescriptions(): List<GeneratorParameterDesc> {
        return GeneratorParameterDesc.all.values.toList()
    }
    fun paramDesc(desc: GeneratorParameterDesc): SharedSecretBuilder {
        parameterDesc = desc
        return this
    }

    fun listKeyGenerators(): List<GeneratorDesc> {
        return algorithm!!.keyPairGenerators
    }
    fun keyGenerator(generator: GeneratorDesc): SharedSecretBuilder {
        keyPairGenerator = generator
        return this
    }

    fun listSecureRandomGenerators(): List<SecureRandomDesc> {
        return SecureRandomDesc.all.values.toList()
    }
    fun secureRandom(secureRandom: SecureRandomDesc): SharedSecretBuilder {
        secureRandomDesc = secureRandom
        return this
    }

    companion object {
        fun create() : SharedSecretBuilder {
            val builder = SharedSecretBuilder()

            builder.algorithm = AlgorithmDesc.toAlgorithm(KeyProperties.KEY_ALGORITHM_EC)
            builder.agreementProvider = KeyAgreementDesc.findKeyAgreement("ECDH")
            builder.keyPairGenerator = builder.algorithm?.keyPairGenerators?.first { generatorDesc ->
                generatorDesc.provider == builder.agreementProvider!!.provider
            }
            builder.parameterDesc = GeneratorParameterDesc.findParameterDesc("NIST P-384")

            return builder

        }
    }
}