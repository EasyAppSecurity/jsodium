package net.easyappsec.sodium.jce.mac;

import com.naphaso.jsodium.Sodium;
import net.easyappsec.sodium.util.BytesUtil;

import javax.crypto.MacSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;

public class SodiumHMacSha512256 extends MacSpi {

    private byte[] keyEncoded;
    private ArrayList<Byte> data = new ArrayList<Byte>();

    @Override
    protected int engineGetMacLength() {
        return Sodium.crypto_auth_BYTES;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.keyEncoded = key.getEncoded();
    }

    @Override
    protected void engineUpdate(byte b) {
        data.add(b);
    }

    @Override
    protected void engineUpdate(byte[] bytes, int i, int i1) {
        for (int j = i; j < i + i1; j++)
            data.add(bytes[j]);
    }

    @Override
    protected byte[] engineDoFinal() {
        byte[] hash = new byte[Sodium.crypto_auth_BYTES];
        Sodium.crypto_auth(hash, BytesUtil.bytes(data), keyEncoded);
        return hash;
    }

    @Override
    protected void engineReset() {
        data = new ArrayList<Byte>();
        keyEncoded = null;
    }
}
