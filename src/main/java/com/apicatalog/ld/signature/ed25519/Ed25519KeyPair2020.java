package com.apicatalog.ld.signature.ed25519;

import java.util.Collection;
import java.util.List;

import com.apicatalog.controller.key.KeyPair;
import com.apicatalog.controller.method.VerificationMethod;
import com.apicatalog.linkedtree.orm.Adapter;
import com.apicatalog.linkedtree.orm.Compaction;
import com.apicatalog.linkedtree.orm.Fragment;
import com.apicatalog.linkedtree.orm.Mapper;
import com.apicatalog.linkedtree.orm.Term;
import com.apicatalog.linkedtree.orm.Type;
import com.apicatalog.linkedtree.orm.Vocab;
import com.apicatalog.multibase.MultibaseAdapter;
import com.apicatalog.multicodec.key.MulticodecKey;
import com.apicatalog.multicodec.key.MulticodecKeyMapper;


@Fragment
@Vocab("https://w3id.org/security#")
public interface Ed25519KeyPair2020 extends KeyPair {
    
    static final String TYPE = "https://w3id.org/security#Ed25519KeyPair2020";

    @Type
    default Collection<String> types() {
        return List.of(TYPE);
    }

    @Term("publicKeyMultibase")
    @Adapter(MultibaseAdapter.class)
    @Mapper(MulticodecKeyMapper.class)
    @Compaction(order = 40)
    @Override
    MulticodecKey publicKey();

    @Term("secretKeyMultibase")
    @Adapter(MultibaseAdapter.class)
    @Mapper(MulticodecKeyMapper.class)
    @Compaction(order = 50)
    @Override
    MulticodecKey privateKey();

    static boolean equals(Ed25519KeyPair2020 k1, Ed25519KeyPair2020 k2) {
        return VerificationMethod.equals(k1, k2)
                && MulticodecKey.equals(k1.publicKey(), k2.publicKey())
                && MulticodecKey.equals(k1.privateKey(), k2.privateKey());
    }
}
