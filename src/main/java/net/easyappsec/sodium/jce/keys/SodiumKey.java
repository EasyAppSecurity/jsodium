package net.easyappsec.sodium.jce.keys;

import java.security.Key;
import java.util.Arrays;

abstract class SodiumKey implements Key {

    protected byte[] bytes;

    public SodiumKey() {
        super();
    }

    public SodiumKey(byte[] bytes) {
        super();
        setBytes(bytes);
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    public String getAlgorithm() {
        return "Sodium";
    }

    public String getFormat() {
        return "Plain";
    }

    public byte[] getEncoded() {
        return bytes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SodiumKey sodiumKey = (SodiumKey) o;
        return Arrays.equals(bytes, sodiumKey.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
