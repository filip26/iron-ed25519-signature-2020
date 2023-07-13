package com.apicatalog.ld.signature.ed25519;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.VerificationMethod;
import com.apicatalog.vc.method.VerificationMethodProcessor;
import com.apicatalog.vc.suite.SignatureSuite;

import jakarta.json.JsonObject;

class MethodProcessor implements VerificationMethodProcessor {

    final SignatureSuite suite;
    
    public MethodProcessor(SignatureSuite suite) {
        this.suite = suite;
    }
    
    @Override
    public VerificationMethod readMethod(JsonObject expanded) throws DocumentError {
        return Ed25519Signature2020Proof.readMethod(suite, expanded);
    }
}
