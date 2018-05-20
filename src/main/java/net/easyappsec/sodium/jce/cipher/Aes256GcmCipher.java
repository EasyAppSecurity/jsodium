package net.easyappsec.sodium.jce.cipher;

import com.naphaso.jsodium.Sodium;
import net.easyappsec.sodium.util.FiveParamFunction;

public class Aes256GcmCipher extends SodiumBaseCipher{

    @Override
    public int getNonceSize() {
        return Sodium.crypto_aead_aes256gcm_NPUBBYTES;
    }

    @Override
    public int getCipherTextSize() {
        return Sodium.crypto_aead_aes256gcm_ABYTES;
    }

    @Override
    public FiveParamFunction<Object, Object, Object, Object, Object, Integer> encryptFunction() {
        FiveParamFunction<Object, Object, Object, Object, Object, Integer> encryptLambda = (ciphertext, plaintext, additionalData, nonce, key) -> {
            return Sodium.crypto_aead_aes256gcm_encrypt(
                    (byte[])ciphertext, (byte[])plaintext,
                    (byte[])additionalData, (byte[])nonce, (byte[])key);
        };
        return encryptLambda;
    }

    @Override
    public FiveParamFunction<Object, Object, Object, Object, Object, Integer> decryptFunction() {
        FiveParamFunction<Object, Object, Object, Object, Object, Integer> encryptLambda = (plaintext, cyphertext, additionalData, nonce, key) -> {
            return Sodium.crypto_aead_aes256gcm_decrypt(
                    (byte[])plaintext, (byte[])cyphertext,
                    (byte[])additionalData, (byte[])nonce, (byte[])key);
        };
        return encryptLambda;
    }
}
