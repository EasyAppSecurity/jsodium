package net.easyappsec.sodium.jce.keys;

import java.security.PrivateKey;

public class SoduimPrivateKey extends SodiumKey implements PrivateKey {

    @Override
    public void setBytes(byte[] bytes) {
        super.setBytes(bytes);
    }

    public SoduimPrivateKey() {
        super();
    }

    public SoduimPrivateKey(byte[] bytes) {
        super(bytes);
    }

}
