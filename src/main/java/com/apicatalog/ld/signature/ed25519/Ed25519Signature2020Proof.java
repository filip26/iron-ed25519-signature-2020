package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.apicatalog.jsonld.schema.LdObject;
import com.apicatalog.jsonld.schema.LdProperty;
import com.apicatalog.jsonld.schema.LdSchema;
import com.apicatalog.jsonld.schema.LdTerm;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.multibase.Multibase.Algorithm;
import com.apicatalog.multicodec.Multicodec.Codec;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.integrity.DataIntegritySchema;
import com.apicatalog.vc.method.VerificationMethodProcessor;
import com.apicatalog.vc.model.Proof;
import com.apicatalog.vc.model.ProofValueProcessor;
import com.apicatalog.vc.suite.SignatureSuite;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;

public final class Ed25519Signature2020Proof implements Proof, ProofValueProcessor {

    static final CryptoSuite CRYPTO = new CryptoSuite(
            Ed25519Signature2020.ID.toString(),
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new Ed25519Signature2020Provider());

    public static final LdTerm VERIFICATION_KEY_TYPE = LdTerm.create("Ed25519VerificationKey2020", VcVocab.SECURITY_VOCAB);

    public static final LdTerm KEY_PAIR_TYPE = LdTerm.create("Ed25519KeyPair2020", VcVocab.SECURITY_VOCAB);

    static final LdSchema METHOD_SCHEMA = DataIntegritySchema.getVerificationKey(
            VERIFICATION_KEY_TYPE,
            DataIntegritySchema.getPublicKey(
                    Algorithm.Base58Btc,
                    Codec.Ed25519PublicKey,
                    key -> key == null || (key.length == 32
                            && key.length == 57
                            && key.length == 114)));

    static final LdProperty<byte[]> PROOF_VALUE_PROPERTY = DataIntegritySchema.getProofValue(
            Algorithm.Base58Btc,
            key -> key.length == 64);

    static final LdSchema PROOF_SCHEMA = DataIntegritySchema.getProof(
            LdTerm.create("Ed25519Signature2020", VcVocab.SECURITY_VOCAB),
            DataIntegritySchema.getEmbeddedMethod(METHOD_SCHEMA),
            PROOF_VALUE_PROPERTY);

    final SignatureSuite suite;
    final CryptoSuite crypto;
    final LdObject ldProof;
    final JsonObject expanded;

    Ed25519Signature2020Proof(SignatureSuite suite,
            CryptoSuite crypto,
            LdObject ldProof,
            JsonObject expanded) {
        this.suite = suite;
        this.crypto = crypto;
        this.ldProof = ldProof;
        this.expanded = expanded;
    }

    @Override
    public VerificationMethod getMethod() {
        return ldProof.value(DataIntegritySchema.VERIFICATION_METHOD);
    }

    @Override
    public byte[] getValue() {
        return ldProof.value(DataIntegritySchema.PROOF_VALUE);
    }

    @Override
    public URI id() {
        return ldProof.value(LdTerm.ID);
    }

    @Override
    public URI previousProof() {
        return ldProof.value(DataIntegritySchema.PREVIOUS_PROOF);
    }

    @Override
    public CryptoSuite getCryptoSuite() {
        return crypto;
    }

    @Override
    public void validate(Map<String, Object> params) throws DocumentError {
        PROOF_SCHEMA.validate(ldProof, params);
    }

    @Override
    public JsonObject toJsonLd() {
        return expanded;
    }

    @Override
    public JsonObject removeProofValue(JsonObject expanded) {
        return Json.createObjectBuilder(expanded).remove(DataIntegritySchema.PROOF_VALUE.uri()).build();
    }

    @Override
    public JsonObject setProofValue(JsonObject expanded, byte[] proofValue) throws DocumentError {
        final JsonValue value = PROOF_VALUE_PROPERTY.write(proofValue);

        return Json.createObjectBuilder(expanded).add(
                DataIntegritySchema.PROOF_VALUE.uri(),
                Json.createArrayBuilder().add(
                        value))
                .build();
    }

    public static final Ed25519Signature2020Proof read(SignatureSuite suite, JsonObject expanded) throws DocumentError {
        final LdObject ldProof = PROOF_SCHEMA.read(expanded);
        return new Ed25519Signature2020Proof(suite, CRYPTO, ldProof, expanded);
    }

    public static final VerificationMethod readMethod(SignatureSuite suite, JsonObject expanded) throws DocumentError {
        return DataIntegritySchema.getEmbeddedMethod(METHOD_SCHEMA).read(expanded);
    }

    @Override
    public ProofValueProcessor valueProcessor() {
        return this;
    }

    @Override
    public String getContext() {
        return "https://w3id.org/security/suites/ed25519-2020/v1";
    }

    @Override
    public VerificationMethodProcessor methodProcessor() {
        return new MethodProcessor(suite);
    }
}