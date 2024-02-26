package com.apicatalog.ld.signature.ed25519;

import java.net.URI;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.node.LdNode;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.vc.VcVocab;
import com.apicatalog.vc.integrity.DataIntegrityVocab;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.method.MethodAdapter;
import com.apicatalog.vc.proof.Proof;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidIssuer;
import com.apicatalog.vc.solid.SolidProofValue;
import com.apicatalog.vc.suite.SignatureSuite;

import jakarta.json.JsonObject;

public final class Ed25519Signature2020 implements SignatureSuite {

    public static final String ID = VcVocab.SECURITY_VOCAB + "Ed25519Signature2020";

    public static final String CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1";

    protected static final MethodAdapter METHOD_ADAPTER = new Ed25519KeyAdapter();

    @Override
    public boolean isSupported(String proofType, JsonObject expandedProof) {
        return ID.equals(proofType);
    }

    @Override
    public Proof getProof(JsonObject document, DocumentLoader loader) throws DocumentError {
        if (document == null) {
            throw new IllegalArgumentException("The 'document' parameter must not be null.");
        }

        final LdNode node = LdNode.of(document);

        final Ed25519Signature2020Proof proof = new Ed25519Signature2020Proof(document);

        proof.id = node.id();

        proof.created = node.scalar(DataIntegrityVocab.CREATED).xsdDateTime();

        proof.purpose = node.node(DataIntegrityVocab.PURPOSE).id();

        proof.domain = node.scalar(DataIntegrityVocab.DOMAIN).string();

        proof.challenge = node.scalar(DataIntegrityVocab.CHALLENGE).string();

        proof.method = node.node(DataIntegrityVocab.VERIFICATION_METHOD).map(METHOD_ADAPTER);

        proof.value = getProofValue(node.scalar(DataIntegrityVocab.PROOF_VALUE).multibase(Multibase.BASE_58_BTC));

        proof.previousProof = node.node(DataIntegrityVocab.PREVIOUS_PROOF).id();

        return proof;
    }

    protected ProofValue getProofValue(byte[] proofValue) {
        return proofValue != null ? new SolidProofValue(proofValue) : null;
    }

    @Override
    public Issuer createIssuer(KeyPair keyPair) {
        return new SolidIssuer(this, keyPair, Multibase.BASE_58_BTC);
    }

    public static Ed25519Signature2020ProofDraft createDraft(VerificationMethod verificationMethod, URI purpose) {
        return new Ed25519Signature2020ProofDraft(verificationMethod, purpose);
    }

    public static Ed25519Signature2020ProofDraft createDraft(URI verificationMethod, URI purpose) {
        return new Ed25519Signature2020ProofDraft(verificationMethod, purpose);
    }
}