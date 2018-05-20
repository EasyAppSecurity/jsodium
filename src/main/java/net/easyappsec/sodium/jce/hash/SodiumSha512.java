package net.easyappsec.sodium.jce.hash;

import com.naphaso.jsodium.Sodium;
import net.easyappsec.sodium.util.FourParamFunction;


public class SodiumSha512 extends BaseSodiumHash {

    @Override
    public int getHashLength() {
        return Sodium.crypto_hash_sha512_BYTES;
    }

    @Override
    public FourParamFunction getHashFunction() {
        FourParamFunction<Object, Object, Integer, Integer, Integer> hashLambda = (out, in, inOffset, inLimit) -> {
            return Sodium.crypto_hash_sha256((byte[])out, (byte[])in, inOffset, inLimit);
        };
        return hashLambda;
    }
}
