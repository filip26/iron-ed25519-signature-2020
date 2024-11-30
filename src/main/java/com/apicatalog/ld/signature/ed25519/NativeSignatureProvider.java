package com.apicatalog.ld.signature.ed25519;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.cryptosuite.CryptoSuiteError;
import com.apicatalog.cryptosuite.CryptoSuiteError.CryptoSuiteErrorCode;
import com.apicatalog.cryptosuite.VerificationError;
import com.apicatalog.cryptosuite.VerificationError.VerificationErrorCode;
import com.apicatalog.cryptosuite.algorithm.SignatureAlgorithm;

class NativeSignatureProvider implements SignatureAlgorithm {

    final String type;

    public NativeSignatureProvider(final String type) {
        this.type = type;
    }

    @Override
    public void verify(final byte[] publicKey, final byte[] signature, final byte[] data) throws VerificationError {
        try {
            java.security.Signature suite = java.security.Signature.getInstance(type);

            suite.initVerify(getPublicKey(publicKey));
            suite.update(data);

            if (!suite.verify(signature)) {
                throw new VerificationError(VerificationErrorCode.InvalidSignature);
            }

        } catch (InvalidKeySpecException | InvalidKeyException
                | NoSuchAlgorithmException | SignatureException e) {
            throw new VerificationError(VerificationErrorCode.InvalidSignature, e);
        }
    }

    @Override
    public byte[] sign(final byte[] privateKey, final byte[] data) throws CryptoSuiteError {

        try {
            java.security.Signature suite = java.security.Signature.getInstance(type);

            suite.initSign(getPrivateKey(privateKey));
            suite.update(data);

            return suite.sign();

        } catch (InvalidKeySpecException | InvalidKeyException
                | NoSuchAlgorithmException | SignatureException e) {
            throw new CryptoSuiteError(CryptoSuiteErrorCode.Signature, e);
        }
    }

    @Override
    public KeyPair keygen() {
        throw new UnsupportedOperationException();
    }

    PublicKey getPublicKey(final byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {

        final KeyFactory kf = KeyFactory.getInstance(type);

        // determine if x was odd.
        boolean xisodd = false;

        int lastbyteInt = publicKey[publicKey.length - 1];

        if ((lastbyteInt & 255) >> 7 == 1) {
            xisodd = true;
        }

        // make public key copy
        byte[] key = new byte[publicKey.length];
        System.arraycopy(publicKey, 0, key, 0, key.length);

        // make sure most significant bit will be 0 - after reversing.
        key[key.length - 1] &= 127;

        key = reverse(key);

        return kf.generatePublic(
                new EdECPublicKeySpec(
                        new NamedParameterSpec(type),
                        new EdECPoint(
                                xisodd,
                                new BigInteger(1, key))));
    }

    PrivateKey getPrivateKey(byte[] privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(type);

        NamedParameterSpec paramSpec = new NamedParameterSpec(type);
        EdECPrivateKeySpec spec = new EdECPrivateKeySpec(paramSpec, privateKey);
        return kf.generatePrivate(spec);
    }

    static final byte[] reverse(byte[] data) {
        final byte[] reversed = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            reversed[data.length - i - 1] = data[i];
        }
        return reversed;
    }
}
