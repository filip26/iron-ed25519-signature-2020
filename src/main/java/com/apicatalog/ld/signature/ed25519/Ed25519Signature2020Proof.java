package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import com.apicatalog.controller.key.VerificationKey;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.VerificationError;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.linkedtree.orm.Adapter;
import com.apicatalog.linkedtree.orm.Context;
import com.apicatalog.linkedtree.orm.Fragment;
import com.apicatalog.linkedtree.orm.Provided;
import com.apicatalog.linkedtree.orm.Term;
import com.apicatalog.linkedtree.orm.Vocab;
import com.apicatalog.linkedtree.xsd.XsdDateTimeAdapter;
import com.apicatalog.vc.model.ModelValidation;
import com.apicatalog.vc.proof.Proof;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidProofValue;
import com.apicatalog.vcdi.VcdiVocab;

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

    @Term("proofValue")
    @Provided
    @Override
    ProofValue signature();

    default CryptoSuite cryptoSuite() {
        return Ed25519Signature2020.CRYPTO;
    }

    @Override
    default void validate(Map<String, Object> params) throws DocumentError {

        ModelValidation.assertNotNull(this::created, VcdiVocab.CREATED);
        ModelValidation.assertNotNull(this::method, VcdiVocab.VERIFICATION_METHOD);
        ModelValidation.assertNotNull(this::purpose, VcdiVocab.PURPOSE);
        ModelValidation.assertNotNull(this::signature, VcdiVocab.PROOF_VALUE);

        // proof value must be 64 bytes
        if (((SolidProofValue) signature()).signature().value().length != 64) {
            throw new DocumentError(ErrorType.Invalid, VcdiVocab.PROOF_VALUE);
        }

        if (method().id() == null) {
            throw new DocumentError(ErrorType.Missing, "VerificationMethodId");
        }

        if (params != null) {
            ModelValidation.assertEquals(params, VcdiVocab.PURPOSE, purpose());
            ModelValidation.assertEquals(params, VcdiVocab.CHALLENGE, challenge());
            ModelValidation.assertEquals(params, VcdiVocab.DOMAIN, domain());
        }
    }
    
    @Override
    default void verify(VerificationKey key) throws VerificationError, DocumentError {
        
        ModelValidation.assertNotNull(this::signature, VcdiVocab.PROOF_VALUE);
        
        if (created() != null && Instant.now().isBefore(created())) {
            throw new DocumentError(ErrorType.Invalid, "Created");
        }
        // verify signature
        signature().verify(key);
    }
}