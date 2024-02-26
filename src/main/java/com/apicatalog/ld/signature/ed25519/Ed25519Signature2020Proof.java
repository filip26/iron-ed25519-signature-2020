package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.Term;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.ld.signature.key.VerificationKey;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.vc.integrity.DataIntegrityVocab;
import com.apicatalog.vc.method.MethodAdapter;
import com.apicatalog.vc.proof.Proof;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidProofValue;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;

public final class Ed25519Signature2020Proof implements Proof, MethodAdapter {

    static final CryptoSuite CRYPTO = new CryptoSuite(
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new Ed25519Signature2020Provider());

    protected URI id;
    protected URI purpose;
    protected VerificationMethod method;
    protected Instant created;
    protected String domain;
    protected String challenge;
    protected ProofValue value;
    protected URI previousProof;

    final JsonObject expanded;

    Ed25519Signature2020Proof(JsonObject expandedProof) {
        this.expanded = expandedProof;
    }

    @Override
    public MethodAdapter methodProcessor() {
        return this;
    }

    @Override
    public JsonObject write(VerificationMethod value) {
        return Ed25519Signature2020.METHOD_ADAPTER.write(value);
    }

    @Override
    public VerificationMethod read(JsonObject document) throws DocumentError {
        return Ed25519Signature2020.METHOD_ADAPTER.read(document);
    }

    @Override
    public void validate(Map<String, Object> params) throws DocumentError {
        if (created == null) {
            throw new DocumentError(ErrorType.Missing, "Created");
        }
        if (method == null) {
            throw new DocumentError(ErrorType.Missing, "VerificationMethod");
        }
        if (purpose == null) {
            throw new DocumentError(ErrorType.Missing, "ProofPurpose");
        }
        if (value == null || ((SolidProofValue)value).toByteArray().length == 0) {
            throw new DocumentError(ErrorType.Missing, "ProofValue");
        }
        // proof value must be 64 bytes
        if (((SolidProofValue)value).toByteArray().length != 64) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        assertEquals(params, DataIntegrityVocab.PURPOSE, purpose.toString()); // TODO compare as URI, expect URI in params
        assertEquals(params, DataIntegrityVocab.CHALLENGE, challenge);
        assertEquals(params, DataIntegrityVocab.DOMAIN, domain);
    }

    protected static void assertEquals(Map<String, Object> params, Term name, String param) throws DocumentError {

        final Object value = params.get(name.name());

        if (value == null) {
            return;
        }

        if (!value.equals(param)) {
            throw new DocumentError(ErrorType.Invalid, name);
        }
    }

    @Override
    public VerificationMethod method() {
        return method;
    }

    @Override
    public ProofValue signature() {
        return value;
    }

    @Override
    public URI id() {
        return id;
    }

    @Override
    public URI previousProof() {
        return previousProof;
    }

    @Override
    public CryptoSuite cryptoSuite() {
        return CRYPTO;
    }
    
    @Override
    public void verify(JsonStructure context, JsonObject data, VerificationKey method) throws VerificationError {
        value.verify(CRYPTO, context, data, unsigned(), method.publicKey());
    }
    
    protected JsonObject unsigned() {
        return Json.createObjectBuilder(expanded).remove(DataIntegrityVocab.PROOF_VALUE.uri()).build();
    }
}