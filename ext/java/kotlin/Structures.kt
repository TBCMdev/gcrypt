package com.example.package.GCrypt;

class NativeLib {

    external fun makeLocalKeyBundle(
        deviceId: Int,
    ): GcryptLocalKeyBundle

    external fun refill(
        numKeys: Int,
    ): GcryptKeyRefillPayload

    companion object {
        init {
            System.loadLibrary("gcrypt")
        }
    }
}
class GcryptKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
)

class GcryptIdKey {
    @JvmField var key: ByteArray? = null
    @JvmField var identifier: Int = 0
}

class GcryptSidKey {
    @JvmField var key: ByteArray? = null
    @JvmField var identifier: Int = 0
    @JvmField var signature: ByteArray? = null
}

class GcryptForeignPreKeyBundle {
    @JvmField var identityKey: ByteArray? = null
    @JvmField var signedPreKey: GcryptSidKey? = null
    @JvmField var quantumPreKey: Any? = null // Holds GcryptSidKey or GcryptIdKey
    @JvmField var oneTimePreKey: GcryptIdKey? = null
}

class GcryptInitialMessageHandshake {
    @JvmField var identityKey: ByteArray? = null
    @JvmField var ephemeralKey: ByteArray? = null
    @JvmField var cipherText: ByteArray? = null
    @JvmField var usedPreKeys: IntArray? = null
    @JvmField var usedQuantumPreKeys: IntArray? = null
}

class GcryptMessagingSession {
    @JvmField var remoteIdentityKey: ByteArray? = null
    @JvmField var rootKey: ByteArray? = null
    @JvmField var sequenceNumber: Int = 0
}

class GcryptSessionInitResult {
    @JvmField var session: GcryptMessagingSession? = null
    @JvmField var handshakeMessage: GcryptInitialMessageHandshake? = null
}