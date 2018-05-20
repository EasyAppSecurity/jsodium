package net.easyappsec.sodium.jce;

import java.security.Provider;

public class SodiumSecurityProvider extends Provider {

    private void initServices(){
        put("MessageDigest.Sha256", "net.easyappsec.sodium.jce.hash.SodiumSha256");
        put("MessageDigest.Sha512", "net.easyappsec.sodium.jce.hash.SodiumSha512");
        put("Cipher.Aes256Gcm", "net.easyappsec.sodium.jce.cipher.Aes256Gcm");
        put("Signature.Sodium", "net.easyappsec.sodium.jce.signature.SodiumSignature");
        put("KeyPairGenerator.Sodium", "net.easyappsec.sodium.jce.keys.SodiumKeyPairGenerator");
        put("Mac.HMacSha512256", "net.easyappsec.sodium.jce.mac.SodiumHMacSha512256");
        put("SecureRandom.Sodium", "net.easyappsec.sodium.jce.random.SodiumRandom");
    }

    public SodiumSecurityProvider() {
        super("Sodium", 1.0, "Sodium Security Provider v1.0");
        initServices();
    }
}
