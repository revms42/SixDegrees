package org.ajar.clique

import org.ajar.clique.encryption.AlgorithmDesc
import org.ajar.clique.encryption.SecureRandomDesc
import org.junit.Test
import java.security.Security
import javax.crypto.KeyGenerator

class DebugTest {

    @Test
    fun runDebugTest() {
        AlgorithmDesc.establishSupportedEncryption()

    }
}