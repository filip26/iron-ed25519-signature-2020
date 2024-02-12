package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.node.LdNode;
import com.apicatalog.ld.node.LdNodeBuilder;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.integrity.DataIntegrityVocab;
import com.apicatalog.vc.method.MethodAdapter;
import com.apicatalog.vc.model.Proof;
import com.apicatalog.vc.suite.SignatureSuite;

import jakarta.json.JsonObject;

public final class Ed25519Signature2020 implements SignatureSuite {

    static final String ID = VcVocab.SECURITY_VOCAB + "Ed25519Signature2020";

//    public static final Term VERIFICATION_KEY_TYPE = Term.create("Ed25519VerificationKey2020", VcVocab.SECURITY_VOCAB);

//    public static final Term KEY_PAIR_TYPE = Term.create("Ed25519KeyPair2020", VcVocab.SECURITY_VOCAB);

    public static final String CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1";

    protected static final MethodAdapter METHOD_ADAPTER = new Ed25519KeyAdapter();

//    protected static final MulticodecDecoder CODECS = MulticodecDecoder.getInstance(KeyCodec.ED25519_PUBLIC_KEY, KeyCodec.ED25519_PRIVATE_KEY);

    protected Ed25519Signature2020() {
        /* protected */
    }

    @Override
    public Proof readProof(JsonObject document) throws DocumentError {
        if (document == null) {
            throw new IllegalArgumentException("The 'document' parameter must not be null.");
        }

        final LdNode node = LdNode.of(document);

        Ed25519Signature2020Proof proof = new Ed25519Signature2020Proof(document);

        proof.id = node.id();

        proof.created = node.scalar(DataIntegrityVocab.CREATED).xsdDateTime();

        proof.purpose = node.node(DataIntegrityVocab.PURPOSE).id();

        proof.domain = node.scalar(DataIntegrityVocab.DOMAIN).string();

        proof.challenge = node.scalar(DataIntegrityVocab.CHALLENGE).string();

        proof.method = node.node(DataIntegrityVocab.VERIFICATION_METHOD).map(METHOD_ADAPTER);

        proof.value = node.scalar(DataIntegrityVocab.PROOF_VALUE).multibase(Multibase.BASE_58_BTC);

        proof.previousProof = node.node(DataIntegrityVocab.PREVIOUS_PROOF).id();

        return proof;
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
        return createDraft(method, purpose, created, domain, null);
    }

    public static Ed25519Signature2020Proof createDraft(
            VerificationMethod method,
            URI purpose,
            Instant created,
            String domain,
            String challenge) throws DocumentError {

        final LdNodeBuilder builder = new LdNodeBuilder();

        builder.type(Ed25519Signature2020.ID);
        builder.set(DataIntegrityVocab.VERIFICATION_METHOD).map(METHOD_ADAPTER, method);
        builder.set(DataIntegrityVocab.CREATED).xsdDateTime(created != null ? created : Instant.now());
        builder.set(DataIntegrityVocab.PURPOSE).id(purpose);

        if (domain != null) {
            builder.set(DataIntegrityVocab.DOMAIN).string(domain);
        }
        if (challenge != null) {
            builder.set(DataIntegrityVocab.CHALLENGE).string(challenge);
        }

        final Ed25519Signature2020Proof proof = new Ed25519Signature2020Proof(builder.build());
        proof.created = created;
        proof.purpose = purpose;
        proof.method = method;
        proof.domain = domain;
        proof.challenge = challenge;

        return proof;
    }
}