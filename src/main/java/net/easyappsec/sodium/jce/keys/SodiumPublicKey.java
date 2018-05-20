package net.easyappsec.sodium.jce.keys;

import java.security.PublicKey;

public class SodiumPublicKey extends SodiumKey implements PublicKey {

    @Override
    public void setBytes(byte[] bytes) {
        super.setBytes(bytes);
    }

    public SodiumPublicKey() {
        super();
    }

    public SodiumPublicKey(byte[] bytes) {
        super(bytes);
    }

}
