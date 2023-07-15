package com.apicatalog.ld.signature.ed25519;

import com.apicatalog.jsonld.schema.LdSchema;
import com.apicatalog.jsonld.schema.LdTerm;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.multibase.Multibase.Algorithm;
import com.apicatalog.multicodec.Multicodec.Codec;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.integrity.DataIntegritySchema;
import com.apicatalog.vc.method.VerificationMethodProcessor;
import com.apicatalog.vc.suite.SignatureSuite;

import jakarta.json.JsonObject;

class MethodProcessor implements VerificationMethodProcessor {

    public static final LdTerm VERIFICATION_KEY_TYPE = LdTerm.create("Ed25519VerificationKey2020", VcVocab.SECURITY_VOCAB);

    public static final LdTerm KEY_PAIR_TYPE = LdTerm.create("Ed25519KeyPair2020", VcVocab.SECURITY_VOCAB);

    static final LdSchema METHOD_SCHEMA = DataIntegritySchema.getVerificationKey(
            VERIFICATION_KEY_TYPE,
            DataIntegritySchema.getPublicKey(
                    Algorithm.Base58Btc,
                    Codec.Ed25519PublicKey,
                    key -> key == null || (key.length == 32
                            || key.length == 57
                            || key.length == 114)));
    
    final SignatureSuite suite;
    
    public MethodProcessor(SignatureSuite suite) {
        this.suite = suite;
    }
    
    @Override
    public VerificationMethod readMethod(JsonObject expanded) throws DocumentError {
        return readMethod(suite, expanded);
    }
    
    public static final VerificationMethod readMethod(SignatureSuite suite, JsonObject expanded) throws DocumentError {
        return DataIntegritySchema.getEmbeddedMethod(METHOD_SCHEMA).read(expanded);
    }
}
