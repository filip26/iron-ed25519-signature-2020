package com.apicatalog.ld.signature.ed25519;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.SchemeRouter;
import com.apicatalog.vc.Vc;

public class Ed25519ContextLoader implements DocumentLoader {

    protected static final Map<String, Document> staticCache = defaultValues();

    protected final DocumentLoader defaultLoader;

    public Ed25519ContextLoader() {
        this.defaultLoader = SchemeRouter.defaultInstance();
    }
    
    public Ed25519ContextLoader(final DocumentLoader defaultLoader) {
        this.defaultLoader = defaultLoader;
    }

    @Override
    public Document loadDocument(final URI url, final DocumentLoaderOptions options) throws JsonLdError {

        if (staticCache.containsKey(url.toString())) {
            final Document document = staticCache.get(url.toString());
            if (document != null) {
                return document;
            }
        }

        return defaultLoader.loadDocument(url, options);
    }

    public static Map<String, Document> defaultValues() {
        Map<String, Document> staticCache = new LinkedHashMap<>();
        staticCache.put(Ed25519Signature2020.CONTEXT, get("security-suites-ed25519-2020-v1.jsonld"));
        return Collections.unmodifiableMap(staticCache);
    }

    protected static JsonDocument get(final String name) {
        try (final InputStream is = Vc.class.getResourceAsStream(name)) {
            return JsonDocument.of(is);

        } catch (IOException | JsonLdError e) {
            e.printStackTrace();
        }
        return null;
    }
}
