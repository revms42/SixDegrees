package org.ajar.clique

import org.ajar.clique.encryption.AlgorithmDesc
import org.ajar.clique.encryption.SecureRandomDesc
import org.junit.Test

class DebugTest {

    @Test
    fun runDebugTest() {
        AlgorithmDesc.establishSupportedEncryption()

        AlgorithmDesc.keyPairAlgorithms.forEach { println(it) }
        println()
        AlgorithmDesc.secretKeyAlgorithms.forEach { println(it) }
        println()
        SecureRandomDesc.all.values.forEach { println(it) }
    }
}