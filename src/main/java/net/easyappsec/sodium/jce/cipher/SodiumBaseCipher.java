package net.easyappsec.sodium.jce.cipher;

import com.naphaso.jsodium.Sodium;
import net.easyappsec.sodium.util.FiveParamFunction;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

abstract class SodiumBaseCipher extends CipherSpi {

    private boolean encryptMode;
    private byte[] secretKey;
    private byte[] nonce;
    private byte[] aad;

    public abstract int getNonceSize();

    public abstract int getCipherTextSize();

    public abstract FiveParamFunction<Object, Object, Object, Object, Object, Integer> encryptFunction();

    public abstract FiveParamFunction<Object, Object, Object, Object, Object, Integer> decryptFunction();

    private void initNonce(){
        this.nonce = new byte[getNonceSize()];
        Sodium.randombytes_buf(nonce);
    }

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {
    }

    @Override
    protected int engineGetBlockSize() {
        return getCipherTextSize();
    }

    @Override
    protected int engineGetOutputSize(int i) {
        return getCipherTextSize();
    }

    @Override
    protected byte[] engineGetIV() {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.encryptMode = (i == 1);
        this.secretKey = key.getEncoded();
        initNonce();
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(i, key, secureRandom);
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(i, key, secureRandom);
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i1) {
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException {
        return 0;
    }

    @Override
    protected void engineUpdateAAD(byte[] bytes, int offset, int len) {
        super.engineUpdateAAD(bytes, offset, len);
        this.aad = new byte[len];
        System.arraycopy(bytes, offset, this.aad, 0, len);
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer byteBuffer) {
        super.engineUpdateAAD(byteBuffer);
        this.aad = byteBuffer.array();
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int i, int i1) throws IllegalBlockSizeException, BadPaddingException {
        byte[] resData = new byte[i1 - i];
        byte[] src = new byte[i1 - i];
        System.arraycopy(bytes, i, src,0, i1);
        if(encryptMode) {
            int ciphertextSize = encryptFunction().apply(resData, src, aad, nonce, secretKey);
            if(ciphertextSize > 0){
                byte[] ciphertextActual = new byte[ciphertextSize];
                System.arraycopy(resData, 0, ciphertextActual, 0, ciphertextSize);
                return ciphertextActual;
            }
        } else {
            int plaintextSize = decryptFunction().apply(resData, src, aad, nonce, secretKey);
            if(plaintextSize > 0){
                byte[] plaintextActual = new byte[plaintextSize];
                System.arraycopy(resData, 0, plaintextActual, 0, plaintextSize);
                return plaintextActual;
            }
        }
        return null;
    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }
}
