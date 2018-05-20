package net.easyappsec.sodium.jce.keys;

import com.naphaso.jsodium.Sodium;

import java.security.*;

public class SodiumKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int PUBLIC_KEY_SIZE_DEFAULT = Sodium.crypto_box_PUBLICKEYBYTES;
    private static final int PRIVATE_KEY_SIZE_DEFAULT = Sodium.crypto_box_SECRETKEYBYTES;

    private int publicKeySize = PUBLIC_KEY_SIZE_DEFAULT;
    private int privateKeySize = PRIVATE_KEY_SIZE_DEFAULT;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.publicKeySize = keysize;
        this.privateKeySize = keysize;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (publicKeySize == 0) {
            publicKeySize = PUBLIC_KEY_SIZE_DEFAULT;
        }

        if (privateKeySize == 0) {
            privateKeySize = PRIVATE_KEY_SIZE_DEFAULT;
        }

        byte[] privKeyBytes = new byte[privateKeySize];
        byte[] publicKeyBytes = new byte[publicKeySize];

        Sodium.crypto_box_keypair(privKeyBytes, publicKeyBytes);

        PublicKey publicKey = new SodiumPublicKey(publicKeyBytes);
        PrivateKey privateKey = new SoduimPrivateKey(privKeyBytes);

        return new KeyPair(publicKey, privateKey);
    }
}
