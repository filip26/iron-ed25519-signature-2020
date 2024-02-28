package com.apicatalog.vc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.json.JsonLdComparison;
import com.apicatalog.jsonld.json.JsonUtils;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.SchemeRouter;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.SigningError;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.ld.signature.ed25519.Ed25519ContextLoader;
import com.apicatalog.ld.signature.ed25519.Ed25519KeyAdapter;
import com.apicatalog.ld.signature.ed25519.Ed25519Signature2020;
import com.apicatalog.ld.signature.ed25519.Ed25519Signature2020ProofDraft;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.vc.integrity.DataIntegrityVocab;
import com.apicatalog.vc.loader.StaticContextLoader;
import com.apicatalog.vc.processor.ExpandedVerifiable;
import com.apicatalog.vc.verifier.Verifier;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;

public class VcTestRunnerJunit {

    private final VcTestCase testCase;

    public final static DocumentLoader LOADER = new UriBaseRewriter(VcTestCase.BASE, "classpath:",
            new Ed25519ContextLoader(
                    new SchemeRouter()
                            .set("classpath", new ClasspathLoader())));

    public final static Ed25519Signature2020 SUITE = new Ed25519Signature2020();

    public final static Verifier VERIFIER = Verifier.with(SUITE).loader(LOADER);

    public VcTestRunnerJunit(VcTestCase testCase) {
        this.testCase = testCase;
    }

    public void execute() {

        assertNotNull(testCase.type);
        assertNotNull(testCase.input);

        try {
            if (testCase.type.contains(VcTestCase.vocab("VeriferTest"))) {

                final Map<String, Object> params = new HashMap<>();
                params.put(DataIntegrityVocab.DOMAIN.name(), testCase.domain);
                params.put(DataIntegrityVocab.CHALLENGE.name(), testCase.challenge);
                params.put(DataIntegrityVocab.PURPOSE.name(), testCase.purpose);

                final Verifiable verifiable = VERIFIER.verify(testCase.input, params);

                assertFalse(isNegative(), "Expected error " + testCase.result);
                assertNotNull(verifiable);

            } else if (testCase.type.contains(VcTestCase.vocab("IssuerTest"))) {

                assertNotNull(testCase.result);

                URI keyPairLocation = testCase.keyPair;

                if (keyPairLocation == null) {
                    // set dummy key pair
                    keyPairLocation = URI.create(VcTestCase.base("issuer/0001-keys.json"));
                }

                // proof draft
                final Ed25519Signature2020ProofDraft draft = Ed25519Signature2020.createDraft(
                        testCase.verificationMethod,
                        URI.create("https://w3id.org/security#assertionMethod"));

                draft.created(testCase.created);
                draft.domain(testCase.domain);
                draft.domain(testCase.challenge);

                final ExpandedVerifiable issued = SUITE.createIssuer(getKeys(keyPairLocation, LOADER))
                        .loader(LOADER)
                        .sign(testCase.input, draft);

                JsonObject doc = null;

                if (testCase.context != null) {

                    doc = issued.compacted(testCase.context);

                } else {
                    doc = issued.expanded();
                }

                assertFalse(isNegative(), "Expected error " + testCase.result);

                assertNotNull(doc);

                final Document expected = LOADER.loadDocument(URI.create((String) testCase.result),
                        new DocumentLoaderOptions());

                boolean match = JsonLdComparison.equals(doc,
                        expected.getJsonContent().orElse(null));

                if (!match) {

                    write(testCase, doc, expected.getJsonContent().orElse(null));

                    fail("Expected result does not match");
                }

            } else {
                fail("Unknown test execution method: " + testCase.type);
                return;
            }

            if (testCase.type.stream().noneMatch(o -> o.endsWith("PositiveEvaluationTest"))) {
                fail();
                return;
            }

        } catch (VerificationError e) {
            assertException(e.getCode() != null ? e.getCode().name() : null, e);

        } catch (SigningError e) {
            assertException(e.getCode() != null ? e.getCode().name() : null, e);

        } catch (DocumentError e) {
            assertException(e.getCode(), e);

        } catch (JsonLdError e) {
            e.printStackTrace();
            fail(e);
        }
    }

    final void assertException(final String code, Throwable e) {

        if (!isNegative()) {
            e.printStackTrace();
            fail(e.getMessage(), e);
            return;
        }

        if (!Objects.equals(testCase.result, code)) {
            e.printStackTrace();
        }

        // compare expected exception
        assertEquals(testCase.result, code);
    }

    final boolean isNegative() {
        return testCase.type.stream().anyMatch(o -> o.endsWith("NegativeEvaluationTest"));
    }

    public static void write(final VcTestCase testCase, final JsonStructure result,
            final JsonStructure expected) {
        final StringWriter stringWriter = new StringWriter();

        try (final PrintWriter writer = new PrintWriter(stringWriter)) {
            writer.println("Test " + testCase.id + ": " + testCase.name);

            final JsonWriterFactory writerFactory = Json.createWriterFactory(
                    Collections.singletonMap(JsonGenerator.PRETTY_PRINTING, true));

            if (expected != null) {
                write(writer, writerFactory, "Expected", expected);
                writer.println();
            }

            if (result != null) {
                write(writer, writerFactory, "Actual", result);
                writer.println();
            }
        }

        System.out.println(stringWriter.toString());
    }

    static final void write(final PrintWriter writer, final JsonWriterFactory writerFactory,
            final String name, final JsonValue result) {

        writer.println(name + ":");

        final StringWriter out = new StringWriter();

        try (final JsonWriter jsonWriter = writerFactory.createWriter(out)) {
            jsonWriter.write(result);
        }

        writer.write(out.toString());
        writer.println();
    }

    static final KeyPair getKeys(URI keyPairLocation, DocumentLoader loader)
            throws DocumentError, JsonLdError {

        final JsonArray keys = JsonLd.expand(keyPairLocation).loader(new Ed25519ContextLoader(new StaticContextLoader(loader))).get();

        for (final JsonValue key : keys) {

            if (JsonUtils.isNotObject(key)) {
                continue;
            }

            return (KeyPair) Ed25519KeyAdapter.from(key.asJsonObject());
        }
        throw new IllegalStateException();
    }

}
