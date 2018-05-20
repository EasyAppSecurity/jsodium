package net.easyappsec.sodium.jce.hash;

import net.easyappsec.sodium.util.BytesUtil;
import net.easyappsec.sodium.util.FourParamFunction;

import java.security.MessageDigestSpi;
import java.util.ArrayList;

abstract class BaseSodiumHash extends MessageDigestSpi implements Cloneable {

    private ArrayList<Byte> data = new ArrayList<Byte>();

    @Override
    protected void engineUpdate(byte input) {
        data.add(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        for (int i = offset; i < offset + len; i++)
            data.add(input[i]);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] bytes = BytesUtil.bytes(data);

        byte[] hash = new byte[engineGetDigestLength()];
        getHashFunction().apply(hash, bytes, 0, bytes.length);

        return hash;
    }

    @Override
    protected void engineReset() {
        data.clear();
    }

    protected int engineGetDigestLength() {
        return getHashLength();
    }

    public abstract int getHashLength();

    public abstract FourParamFunction getHashFunction();

}
