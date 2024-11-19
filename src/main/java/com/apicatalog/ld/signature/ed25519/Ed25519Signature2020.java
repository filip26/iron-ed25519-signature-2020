package com.apicatalog.ld.signature.ed25519;

import java.net.URI;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.controller.method.VerificationMethod;
import com.apicatalog.cryptosuite.CryptoSuite;
import com.apicatalog.cryptosuite.primitive.MessageDigest;
import com.apicatalog.cryptosuite.primitive.Urdna2015;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.linkedtree.Linkable;
import com.apicatalog.linkedtree.adapter.NodeAdapterError;
import com.apicatalog.linkedtree.builder.TreeBuilderError;
import com.apicatalog.linkedtree.fragment.FragmentPropertyError;
import com.apicatalog.linkedtree.jsonld.JsonLdType;
import com.apicatalog.linkedtree.jsonld.io.JsonLdTreeReader;
import com.apicatalog.linkedtree.literal.ByteArrayValue;
import com.apicatalog.linkedtree.orm.mapper.TreeReaderMapping;
import com.apicatalog.linkedtree.orm.proxy.PropertyValueConsumer;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multibase.MultibaseAdapter;
import com.apicatalog.vc.issuer.Issuer;
import com.apicatalog.vc.model.VerifiableMaterial;
import com.apicatalog.vc.model.generic.GenericMaterial;
import com.apicatalog.vc.proof.Proof;
import com.apicatalog.vc.proof.ProofValue;
import com.apicatalog.vc.solid.SolidIssuer;
import com.apicatalog.vc.solid.SolidProofValue;
import com.apicatalog.vc.suite.SignatureSuite;
import com.apicatalog.vcdi.VcdiVocab;
import com.apicatalog.vcdm.VcdmVocab;

import jakarta.json.Json;

public final class Ed25519Signature2020 implements SignatureSuite {

    private static final Logger LOGGER = Logger.getLogger(Ed25519Signature2020.class.getName());

    public static final String ID = VcdmVocab.SECURITY_VOCAB + "Ed25519Signature2020";

    public static final String CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1";

    static final TreeReaderMapping MAPPING = TreeReaderMapping.createBuilder()
            .scan(Ed25519Signature2020Proof.class, true)
            .scan(Ed25519VerificationKey2020.class, true)
            .with(new MultibaseAdapter())
            .build();

    static final JsonLdTreeReader READER = JsonLdTreeReader.of(MAPPING);

    static final CryptoSuite CRYPTO = new CryptoSuite(
            "Ed25519",
            32, // 57, 114 //FIXMe
            new Urdna2015(),
            new MessageDigest("SHA-256"),
            new Ed25519Signature2020Provider());

//
//    protected ProofValue getProofValue(byte[] proofValue) {
//        return proofValue != null ? new SolidProofValue(proofValue) : null;
//    }
//
    @Override
    public Issuer createIssuer(KeyPair keyPair) {
        return new SolidIssuer(this, CRYPTO, keyPair, Multibase.BASE_58_BTC);
    }

    public static Ed25519Signature2020ProofDraft createDraft(VerificationMethod verificationMethod, URI purpose) {
        return new Ed25519Signature2020ProofDraft(verificationMethod, purpose);
    }

    public static Ed25519Signature2020ProofDraft createDraft(URI verificationMethod, URI purpose) {
        return new Ed25519Signature2020ProofDraft(verificationMethod, purpose);
    }

    @Override
    public boolean isSupported(VerifiableMaterial verifiable, VerifiableMaterial proof) {

        Collection<String> proofType = JsonLdType.strings(proof.expanded());

        return proofType != null && proofType.contains(ID);
    }

    @Override
    public Proof getProof(VerifiableMaterial verifiable, VerifiableMaterial proofMaterial, DocumentLoader loader) throws DocumentError {
        try {
            Proof proof = READER.read(Proof.class, Json.createArrayBuilder().add(proofMaterial.expanded()).build());
            if (proof == null) {
                return null;
            }

            if (proof instanceof PropertyValueConsumer consumer
                    && proof instanceof Linkable linkable) {

                final ByteArrayValue signature = linkable.ld().asFragment()
                        .literal(VcdiVocab.PROOF_VALUE.uri(), ByteArrayValue.class);

                ProofValue proofValue = null;

                if (signature != null) {
                    final VerifiableMaterial unsignedProof = new GenericMaterial(
                            proofMaterial.context(),
                            Json.createObjectBuilder(proofMaterial.compacted())
                                    .remove(VcdiVocab.PROOF_VALUE.name()).build(),
                            Json.createObjectBuilder(proofMaterial.expanded())
                                    .remove(VcdiVocab.PROOF_VALUE.uri()).build());

                    proofValue = getProofValue(verifiable, unsignedProof, signature.byteArrayValue(), loader);
                    consumer.acceptFragmentPropertyValue("signature", proofValue);
                }
            }

            return proof;

        } catch (FragmentPropertyError e) {
            throw new DocumentError(e, ErrorType.Invalid, e.getPropertyName());

        } catch (TreeBuilderError e) {
            if (e.term() != null) {
                throw new DocumentError(e, ErrorType.Invalid, e.term());
            }
            throw new DocumentError(e, ErrorType.Invalid, "Proof", e.term());

        } catch (NodeAdapterError e) {
            throw new DocumentError(e, ErrorType.Invalid, "Proof");
        }
    }

    protected ProofValue getProofValue(VerifiableMaterial data, VerifiableMaterial proof, byte[] proofValue, DocumentLoader loader) throws DocumentError {
        if (proofValue == null) {
            return null;
        }

        if (proofValue.length != 64) {
            LOGGER.log(Level.WARNING, "Invalid proof value length [{0}]. Expected 64 bytes.", proofValue.length);
            throw new DocumentError(ErrorType.Invalid, "ProofValueLength");
        }
        return SolidProofValue.of(CRYPTO, data, proof, proofValue);
    }
}