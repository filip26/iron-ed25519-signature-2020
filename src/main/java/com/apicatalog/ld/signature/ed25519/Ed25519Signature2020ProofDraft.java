package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;

import com.apicatalog.controller.method.VerificationMethod;
import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.linkedtree.adapter.NodeAdapterError;
import com.apicatalog.linkedtree.builder.FragmentComposer;
import com.apicatalog.linkedtree.fragment.FragmentPropertyError;
import com.apicatalog.linkedtree.jsonld.JsonLdContext;
import com.apicatalog.linkedtree.jsonld.JsonLdKeyword;
import com.apicatalog.linkedtree.jsonld.io.JsonLdWriter;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.vc.issuer.ProofDraft;
import com.apicatalog.vc.model.ModelValidation;
import com.apicatalog.vc.model.VerifiableMaterial;
import com.apicatalog.vc.model.generic.GenericMaterial;
import com.apicatalog.vcdi.VcdiVocab;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;

public final class Ed25519Signature2020ProofDraft extends ProofDraft {

    protected static final JsonLdWriter WRITER = new JsonLdWriter()
            .scan(Ed25519Signature2020Proof.class)
            .scan(Ed25519VerificationKey2020.class)
            .scan(VerificationMethod.class);

    protected String domain;
    protected String challenge;
    protected String nonce;

    protected Ed25519Signature2020ProofDraft(VerificationMethod method) {
        super(Ed25519Signature2020.ID, method);
    }

    public Ed25519Signature2020ProofDraft challenge(String challenge) {
        this.challenge = challenge;
        return this;
    }

    public Ed25519Signature2020ProofDraft domain(String domain) {
        this.domain = domain;
        return this;
    }

    public Ed25519Signature2020ProofDraft nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    @Override
    public VerifiableMaterial unsigned(Collection<String> documentContext, DocumentLoader loader, URI base) throws DocumentError {

        try {
            Ed25519Signature2020Proof proof = FragmentComposer.create()
                    .set("id", id)
                    .set("purpose", purpose)
                    .set("created", created)
                    .set("expires", expires)
                    .set("method", method)
                    .set(VcdiVocab.PREVIOUS_PROOF.name(), previousProof)
                    .set(VcdiVocab.CHALLENGE.name(), challenge)
                    .set(VcdiVocab.NONCE.name(), nonce)
                    .set(VcdiVocab.DOMAIN.name(), domain)
                    .get(Ed25519Signature2020Proof.class);

            JsonObject compacted = WRITER.compacted(proof);

            JsonArray expanded = JsonLd.expand(JsonDocument.of(compacted)).loader(loader).base(base).get();

            Collection<String> context = documentContext;

            if (compacted.containsKey(JsonLdKeyword.CONTEXT)) {
                context = JsonLdContext.strings(compacted, context);
                compacted = Json.createObjectBuilder(compacted).remove(JsonLdKeyword.CONTEXT).build();
            }

            return new GenericMaterial(
                    context,
                    compacted,
                    expanded.iterator().next().asJsonObject());

        } catch (FragmentPropertyError e) {
            throw DocumentError.of(e);

        } catch (NodeAdapterError e) {
            throw new DocumentError(e, ErrorType.Invalid);

        } catch (JsonLdError e) {
            throw new DocumentError(e, ErrorType.Invalid);
        }
    }

    @Override
    protected VerifiableMaterial sign(VerifiableMaterial proof, byte[] signature) throws DocumentError {

        JsonValue value = Json.createValue(Multibase.BASE_58_BTC.encode(signature));

        JsonObject compacted = Json.createObjectBuilder(proof.compacted()).add(VcdiVocab.PROOF_VALUE.name(), value).build();
        JsonObject expanded = proof.expanded(); // FIXME

        return new GenericMaterial(
                proof.context(),
                compacted,
                expanded);
    }

    public String domain() {
        return domain;
    }

    public String challenge() {
        return challenge;
    }

    public String nonce() {
        return nonce;
    }

    public Ed25519Signature2020ProofDraft created(Instant created) {
        this.created = created == null
                ? created
                : created.truncatedTo(ChronoUnit.SECONDS);
        return this;
    }

    public Ed25519Signature2020ProofDraft expires(Instant expires) {
        this.expires = expires == null
                ? expires
                : expires.truncatedTo(ChronoUnit.SECONDS);
        return this;
    }

    @Override
    public void validate() throws DocumentError {
        ModelValidation.assertNotNull(this::purpose, VcdiVocab.PURPOSE);

        if (method() != null && method().id() == null) {
            throw new DocumentError(ErrorType.Missing, "VerificationMethodId");
        }

        if (created() != null && expires() != null && created().isAfter(expires())) {
            throw new DocumentError(ErrorType.Invalid, "ValidityPeriod");
        }
    }
}