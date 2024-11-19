package com.apicatalog.ld.signature.ed25519;

import java.net.URI;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.controller.key.VerificationKey;
import com.apicatalog.controller.method.VerificationMethod;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.DocumentError.ErrorType;
import com.apicatalog.ld.VocabTerm;
import com.apicatalog.linkedtree.LinkedFragment;
import com.apicatalog.linkedtree.adapter.NodeAdapterError;
import com.apicatalog.linkedtree.orm.Term;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.vc.method.MethodAdapter;
import com.apicatalog.vcdm.VcdmVocab;

import jakarta.json.JsonObject;

@Deprecated
public class Ed25519KeyAdapter implements MethodAdapter {

    public static final URI VERIFICATION_KEY_TYPE_URI = URI.create(VcdmVocab.SECURITY_VOCAB + "Ed25519VerificationKey2020");

    public static final URI KEY_PAIR_TYPE_URI = URI.create(VcdmVocab.SECURITY_VOCAB + "Ed25519KeyPair2020");

    public static final VocabTerm CONTROLLER = VocabTerm.create("controller", VcdmVocab.SECURITY_VOCAB);

    public static final VocabTerm PUBLIC_KEY = VocabTerm.create("publicKeyMultibase", VcdmVocab.SECURITY_VOCAB);
    public static final VocabTerm PRIVATE_KEY = VocabTerm.create("privateKeyMultibase", VcdmVocab.SECURITY_VOCAB);

//    @Override
//    public VerificationMethod read(JsonObject document) throws DocumentError {
//        return from(document);
//    }
//
    public static VerificationMethod from(JsonObject document) throws DocumentError {
        if (document == null) {
            throw new IllegalArgumentException("Verification method cannot be null.");
        }
//
//        final LdNode node = LdNode.of(document);
//
//        final URI id = node.id();
//        final URI controller = node.node(CONTROLLER).id();
//
//        URI type = null;
//
//        byte[] publicKey = null;
//        byte[] privateKey = null;
//
//        if (node.type().hasType(KEY_PAIR_TYPE_URI.toString())) {
//
//            type = KEY_PAIR_TYPE_URI;
//
//            publicKey = getKey(node, PUBLIC_KEY, KeyCodec.ED25519_PUBLIC_KEY);
//            privateKey = getKey(node, PRIVATE_KEY, KeyCodec.ED25519_PRIVATE_KEY);
//
//        } else if (node.type().hasType(VERIFICATION_KEY_TYPE_URI.toString())) {
//
//            type = VERIFICATION_KEY_TYPE_URI;
//
//            publicKey = getKey(node, PUBLIC_KEY, KeyCodec.ED25519_PUBLIC_KEY);
//
//        } else if (node.type().exists()) {
//            throw new DocumentError(ErrorType.Invalid, "VerificationMethodType");
//        }
//
//        // validate public key
//        if (publicKey != null && publicKey.length != 32
//                && publicKey.length != 57
//                && publicKey.length != 114) {
//            throw new DocumentError(ErrorType.Invalid, "PublicKeyLength");
//        }
//
//        return new Ed25519KeyPair2020(
//                id,
//                controller,
//                type,
//                publicKey,
//                privateKey);
        return null;
    }
//
//    protected static final byte[] getKey(final LdNode node, final Term term, final Multicodec codec) throws DocumentError {
//
//        final LdScalar key = node.scalar(term);
//
//        if (key.exists()) {
//
//            if (!"https://w3id.org/security#multibase".equals(key.type())) {
//                throw new DocumentError(ErrorType.Invalid, term.name() + "Type");
//            }
//
//            final String encodedKey = key.string();
//
//            if (!Multibase.BASE_58_BTC.isEncoded(encodedKey)) {
//                throw new DocumentError(ErrorType.Invalid, term.name() + "Type");
//            }
//
//            final byte[] decodedKey = Multibase.BASE_58_BTC.decode(encodedKey);
//
//            return codec.decode(decodedKey);
//        }
//
//        return null;
//    }

//    @Override
//    public JsonObject write(VerificationMethod value) {
//
//        LdNodeBuilder builder = new LdNodeBuilder();
//
//        if (value.id() != null) {
//            builder.id(value.id());
//        }
//
//        boolean embedded = false;
//
//        if (value.controller() != null) {
//            builder.set(CONTROLLER).id(value.controller());
//            embedded = true;
//        }
//
//        if (value instanceof VerificationKey) {
//            VerificationKey verificationKey = (VerificationKey) value;
//
//            if (verificationKey.publicKey() != null) {
//                builder.set(PUBLIC_KEY)
//                        .scalar("https://w3id.org/security#multibase",
//                                Multibase.BASE_58_BTC.encode(
//                                        KeyCodec.ED25519_PUBLIC_KEY
//                                                .encode(verificationKey.publicKey())));
//                ;
//                embedded = true;
//            }
//        }
//
//        if (value instanceof KeyPair) {
//            KeyPair keyPair = (KeyPair) value;
//
//            if (keyPair.privateKey() != null) {
//                builder.set(PRIVATE_KEY)
//                        .scalar("https://w3id.org/security#multibase",
//                                Multibase.BASE_58_BTC.encode(
//                                        KeyCodec.ED25519_PRIVATE_KEY
//                                                .encode(keyPair.privateKey())));
//                ;
//                embedded = true;
//            }
//        }
//
//        if (embedded) {
//            builder.type(value.type().toASCIIString());
//        }
//
//        return builder.build();
//    }

    @Override
    public String type() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Class<?> typeInterface() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Object materialize(LinkedFragment source) throws NodeAdapterError {
        // TODO Auto-generated method stub
        return null;
    }
}
