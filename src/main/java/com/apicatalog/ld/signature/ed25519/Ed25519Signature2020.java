package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.apicatalog.jsonld.schema.LdObject;
import com.apicatalog.jsonld.schema.LdTerm;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.integrity.DataIntegritySchema;
import com.apicatalog.vc.model.Proof;
import com.apicatalog.vc.suite.SignatureSuite;

import jakarta.json.JsonObject;

public final class Ed25519Signature2020 implements SignatureSuite {

    static final String ID = VcVocab.SECURITY_VOCAB + "Ed25519Signature2020";

    public static final LdTerm VERIFICATION_KEY_TYPE = LdTerm.create("Ed25519VerificationKey2020", VcVocab.SECURITY_VOCAB);

    public static final LdTerm KEY_PAIR_TYPE = LdTerm.create("Ed25519KeyPair2020", VcVocab.SECURITY_VOCAB);

    static final URI CONTEXT = URI.create("https://w3id.org/security/suites/ed25519-2020/v1");

    @Override
    public Proof readProof(JsonObject expanded) throws DocumentError {
        return Ed25519Signature2020Proof.read(this, expanded);
    }

    @Override
    public boolean isSupported(String proofType, JsonObject expandedProof) {
        return ID.equals(proofType);
    }

    public static Ed25519Signature2020Proof createDraft(
            VerificationMethod method,
            URI purpose,
            Instant created,
            String domain) throws DocumentError {

        Map<String, Object> proof = new LinkedHashMap<>();

        proof.put(LdTerm.TYPE.uri(), URI.create(Ed25519Signature2020.ID));
        proof.put(DataIntegritySchema.CREATED.uri(), created);
        proof.put(DataIntegritySchema.PURPOSE.uri(), purpose);
        proof.put(DataIntegritySchema.VERIFICATION_METHOD.uri(), method);
        proof.put(DataIntegritySchema.DOMAIN.uri(), domain);
//      proof.put(DataIntegritySchema.CHALLENGE.uri(), challenge);

        final LdObject ldProof = new LdObject(proof);

        final JsonObject expanded = Ed25519Signature2020Proof.PROOF_SCHEMA.write(ldProof);

        return new Ed25519Signature2020Proof(
                Ed25519Signature2020Proof.CRYPTO,
                new MethodProcessor(new Ed25519Signature2020()),
                ldProof,
                expanded);
    }
}