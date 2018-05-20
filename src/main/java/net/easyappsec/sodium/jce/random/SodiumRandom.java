package net.easyappsec.sodium.jce.random;

import com.naphaso.jsodium.Sodium;

import java.security.SecureRandom;

public class SodiumRandom extends SecureRandom {

    protected void engineSetSeed(byte[] seed) {
        Sodium.randombytes_stir();
    }

    protected void engineNextBytes(byte[] bytes) {
        Sodium.randombytes(bytes);
    }

    protected byte[] engineGenerateSeed(int numBytes) {
        byte[] buffer = new byte[numBytes];
        Sodium.randombytes_buf(buffer);
        return buffer;
    }
}
