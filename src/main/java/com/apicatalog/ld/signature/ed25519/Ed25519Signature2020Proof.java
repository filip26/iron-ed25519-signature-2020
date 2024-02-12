package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.Term;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.node.LdNodeBuilder;
import com.apicatalog.ld.signature.CryptoSuite;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.ld.signature.primitive.MessageDigest;
import com.apicatalog.ld.signature.primitive.Urdna2015;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.vc.integrity.DataIntegrityVocab;
import com.apicatalog.vc.method.MethodAdapter;
import com.apicatalog.vc.model.Proof;
import com.apicatalog.vc.model.ProofValueProcessor;

import jakarta.json.Json;
import jakarta.json.JsonObject;

public final class Ed25519Signature2020Proof implements Proof, ProofValueProcessor, MethodAdapter {

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
    protected byte[] value;
    protected URI previousProof;

    final JsonObject expanded;

    Ed25519Signature2020Proof(JsonObject expandedProof) {
        this.expanded = expandedProof;
    }

    /**
     * The intent for the proof, the reason why an entity created it. Mandatory e.g.
     * assertion or authentication
     *
     * @see <a href=
     *      "https://w3c-ccg.github.io/data-integrity-spec/#proof-purposes">Proof
     *      Purposes</a>
     *
     * @return {@link URI} identifying the purpose
     */
    public URI getPurpose() {
        return purpose;
    }

    @Override
    public VerificationMethod getMethod() {
        return method;
    }

    /**
     * The string value of an ISO8601. Mandatory
     *
     * @return the date time when the proof has been created
     */
    public Instant getCreated() {
        return created;
    }

    /**
     * A string value specifying the restricted domain of the proof.
     *
     * @return the domain or <code>null</code>
     */
    public String getDomain() {
        return domain;
    }

    /**
     * A string value used once for a particular domain and/or time. Used to
     * mitigate replay attacks.
     * 
     * @return the challenge or <code>null</code>
     */
    public String getChallenge() {
        return challenge;
    }

    @Override
    public byte[] getValue() {
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
    public CryptoSuite getCryptoSuite() {
        return CRYPTO;
    }

    @Override
    public JsonObject toJsonLd() {
        return expanded;
    }

    @Override
    public JsonObject removeProofValue(JsonObject expanded) {
        return Json.createObjectBuilder(expanded).remove(DataIntegrityVocab.PROOF_VALUE.uri()).build();
    }

    @Override
    public JsonObject setProofValue(JsonObject expanded, byte[] proofValue) throws DocumentError {
        LdNodeBuilder node = new LdNodeBuilder(Json.createObjectBuilder(expanded));

        node.set(DataIntegrityVocab.PROOF_VALUE).multibase(
                Multibase.BASE_58_BTC, proofValue);

        return node.build();
    }

    @Override
    public ProofValueProcessor valueProcessor() {
        return this;
    }

    @Override
    public String getContext() {
        return Ed25519Signature2020.CONTEXT;
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
        if (value == null || value.length == 0) {
            throw new DocumentError(ErrorType.Missing, "ProofValue");
        }
        // proof value must be 64 bytes
        if (value.length != 64) {
            throw new DocumentError(ErrorType.Invalid, "ProofValue");
        }

        assertEquals(params, DataIntegrityVocab.PURPOSE, purpose.toString()); //TODO compare as URI, expect URI in params
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
}