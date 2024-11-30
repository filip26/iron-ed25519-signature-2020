package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.controller.key.VerificationKey;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.VerificationError;
import com.apicatalog.cryptosuite.VerificationError.VerificationErrorCode;
import com.apicatalog.linkedtree.orm.Adapter;
import com.apicatalog.linkedtree.orm.Context;
import com.apicatalog.linkedtree.orm.Fragment;
import com.apicatalog.linkedtree.orm.Provided;
import com.apicatalog.linkedtree.orm.Term;
import com.apicatalog.linkedtree.orm.Vocab;
import com.apicatalog.linkedtree.xsd.XsdDateTimeAdapter;
import com.apicatalog.vc.di.VcdiVocab;
import com.apicatalog.vc.model.DocumentError;
import com.apicatalog.vc.model.ModelAssertions;
import com.apicatalog.vc.model.DocumentError.ErrorType;
import com.apicatalog.vc.proof.Proof;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidProofValue;

@Fragment
@Term("Ed25519Signature2020")
@Vocab("https://w3id.org/security#")
@Context("https://w3id.org/security/suites/ed25519-2020/v1")
public interface Ed25519Signature2020Proof extends Proof {

    @Term("proofPurpose")
    @Override
    URI purpose();

    /**
     * The string value of an ISO8601. Mandatory
     *
     * @return the date time when the proof has been created
     */
    @Vocab("http://purl.org/dc/terms/")
    @Adapter(XsdDateTimeAdapter.class)
    Instant created();

    @Adapter(XsdDateTimeAdapter.class)
    @Term(value = "expiration", compact = false)
    Instant expires();
    
    /**
     * A string value specifying the restricted domain of the proof.
     *
     * @return the domain or <code>null</code>
     */
    @Term
    String domain();

    /**
     * A string value used once for a particular domain and/or time. Used to
     * mitigate replay attacks.
     * 
     * @return the challenge or <code>null</code>
     */
    @Term
    String challenge();

    @Term
    String nonce();
    
    @Term("proofValue")
    @Provided
    @Override
    ProofValue signature();

    default CryptoSuite cryptoSuite() {
        return Ed25519Signature2020.CRYPTO;
    }

    @Override
    default void validate(Map<String, Object> params) throws DocumentError {

        ModelAssertions.assertNotNull(this::created, VcdiVocab.CREATED);
        ModelAssertions.assertNotNull(this::method, VcdiVocab.VERIFICATION_METHOD);
        ModelAssertions.assertNotNull(this::purpose, VcdiVocab.PURPOSE);
        ModelAssertions.assertNotNull(this::signature, VcdiVocab.PROOF_VALUE);

        // proof value must be 64 bytes
        if (((SolidProofValue) signature()).signature().byteArrayValue().length != 64) {
            throw new DocumentError(ErrorType.Invalid, VcdiVocab.PROOF_VALUE);
        }

        if (method().id() == null) {
            throw new DocumentError(ErrorType.Missing, "VerificationMethodId");
        }
        
        if (created() != null && expires() != null && created().isAfter(expires())) {
            throw new DocumentError(ErrorType.Invalid, "ValidityPeriod");
        }


        if (params != null) {
            ModelAssertions.assertEquals(params, VcdiVocab.PURPOSE, purpose());
            ModelAssertions.assertEquals(params, VcdiVocab.CHALLENGE, challenge());
            ModelAssertions.assertEquals(params, VcdiVocab.DOMAIN, domain());
            ModelAssertions.assertEquals(params, VcdiVocab.NONCE, nonce());
        }
    }
    
    @Override
    default void verify(VerificationKey key) throws VerificationError, DocumentError {
        
        ModelAssertions.assertNotNull(this::signature, VcdiVocab.PROOF_VALUE);
        
        if (created() != null && Instant.now().isBefore(created())) {
            throw new DocumentError(ErrorType.Invalid, "Created");
        }
        
        if (expires() != null && Instant.now().isAfter(expires())) {
            throw new VerificationError(VerificationErrorCode.Expired);
        }
        
        // verify signature
        signature().verify(key);
    }
}