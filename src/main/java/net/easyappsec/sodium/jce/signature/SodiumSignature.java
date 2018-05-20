package net.easyappsec.sodium.jce.signature;

import com.naphaso.jsodium.Sodium;
import net.easyappsec.sodium.util.BytesUtil;

import java.security.*;
import java.util.ArrayList;

public class SodiumSignature extends SignatureSpi {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private ArrayList<Byte> data = new ArrayList<Byte>();

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.data  = new ArrayList<Byte>();
        this.publicKey = publicKey;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.data = new ArrayList<>();
        this.privateKey = privateKey;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        data.add(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        for (int i = off; i<len; i++){
            data.add(b[i]);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (data == null || data.size() == 0){
            throw new SignatureException("Signed data is empty!");
        }
        byte[] sign = new byte[Sodium.crypto_sign_BYTES + data.size()];
        if (Sodium.crypto_sign(sign, BytesUtil.bytes(data), privateKey.getEncoded()) <=0){
            throw new SignatureException("Internal error while signing");
        }
        return sign;
    }

    @Override
    protected boolean engineVerify(byte[] signature) throws SignatureException {
        if (signature == null || signature.length == 0){
            throw new SignatureException("Signature is empty!");
        }
        return Sodium.crypto_sign_verify_detached(signature, BytesUtil.bytes(data), publicKey.getEncoded())>=0;
    }
}
