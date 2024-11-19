package com.apicatalog.ld.signature.ed25519;

import com.apicatalog.controller.key.VerificationKey;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.linkedtree.adapter.NodeAdapterError;
import com.apicatalog.linkedtree.builder.TreeBuilderError;
import com.apicatalog.linkedtree.fragment.FragmentPropertyError;
import com.apicatalog.linkedtree.jsonld.io.JsonLdReader;
import com.apicatalog.linkedtree.orm.mapper.TreeReaderMapping;
import com.apicatalog.vc.method.resolver.VerificationKeyProvider;
import com.apicatalog.vc.proof.Proof;

import jakarta.json.JsonStructure;

public class Ed25519VerificationKey2020Provider implements VerificationKeyProvider {

    static TreeReaderMapping MAPPING = TreeReaderMapping
            .createBuilder()
            .scan(Ed25519VerificationKey2020.class)
            .build();

    static JsonLdReader READER = JsonLdReader.of(MAPPING, Ed25519ContextLoader.resources());

    protected final DocumentLoader loader;

    public Ed25519VerificationKey2020Provider(DocumentLoader loader) {
        this.loader = loader;
    }

    @Override
    public VerificationKey keyFor(Proof proof) throws DocumentError {

        if (proof == null || proof.method() == null || proof.method().id() == null) {
            return null;
        }

        try {
            Document doc = loader.loadDocument(proof.method().id(), new DocumentLoaderOptions());

            JsonStructure json = doc.getJsonContent().orElseThrow(() -> new DocumentError(ErrorType.Invalid));

            return READER.read(Ed25519VerificationKey2020.class, json.asJsonObject());

        } catch (FragmentPropertyError e) {
            throw DocumentError.of(e);

        } catch (JsonLdError | NodeAdapterError | TreeBuilderError e) {
            throw new DocumentError(e, ErrorType.Invalid);
        }
    }

}
