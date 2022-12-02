package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.util.Objects;

import com.apicatalog.ld.schema.LdTerm;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.multibase.Multibase.Algorithm;
import com.apicatalog.multicodec.Multicodec.Codec;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.integrity.DataIntegrity;
import com.apicatalog.vc.integrity.DataIntegritySuite;

public final class Ed25519Signature2020 extends DataIntegritySuite {

    public static final LdTerm ID = LdTerm.create("Ed25519Signature2020", VcVocab.SECURITY_VOCAB);
    
    public static final LdTerm VERIFICATION_KEY_TYPE = LdTerm.create("Ed25519VerificationKey2020", VcVocab.SECURITY_VOCAB);
    
    public static final LdTerm KEY_PAIR_TYPE = LdTerm.create("Ed25519KeyPair2020", VcVocab.SECURITY_VOCAB);
    
    static final URI CONTEXT = URI.create( "https://w3id.org/security/suites/ed25519-2020/v1");

    static final CryptoSuite CRYPTO = new CryptoSuite(
            ID,
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new Ed25519Signature2020Provider()
            );

    public Ed25519Signature2020() {
        super(ID, CONTEXT, CRYPTO, 
                DataIntegrity.getProof(
                        ID, 
                        Algorithm.Base58Btc,
                        key -> key.length == 64,
                        DataIntegrity.getVerificationKey(
                                VERIFICATION_KEY_TYPE, 
                                DataIntegrity.getPublicKey(
                                    Algorithm.Base58Btc, 
                                    Codec.Ed25519PublicKey, 
                                    key -> key == null || (key.length == 32
                                        && key.length == 57
                                        && key.length == 114
                                            )
                                    ))
                        ));
    }

    public static boolean isTypeOf(final String type) {
        return Objects.equals(ID.uri(), type);
    }
}