# Iron Ed25519 Signature 2020 Cryptosuite

An implementation of the [W3C Ed25519Signature2020 Cryptosuite](https://www.w3.org/TR/vc-di-eddsa/#the-ed25519signature2020-suite) in Java.

[![Java 17 CI](https://github.com/filip26/iron-ed25519-cryptosuite-2020/actions/workflows/java17-build.yml/badge.svg)](https://github.com/filip26/iron-ed25519-cryptosuite-2020/actions/workflows/java17-build.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/827b291e7e72417996e4167d37a25783)](https://app.codacy.com/gh/filip26/iron-ed25519-cryptosuite-2020/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/827b291e7e72417996e4167d37a25783)](https://app.codacy.com/gh/filip26/iron-ed25519-cryptosuite-2020/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=filip26_iron-ed25519-cryptosuite-2020&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=filip26_iron-ed25519-cryptosuite-2020)
[![Maven Central](https://img.shields.io/maven-central/v/com.apicatalog/iron-ed25519-cryptosuite-2020.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:com.apicatalog%20AND%20a:iron-ed25519-cryptosuite-2020)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features
* [Ed25519Signature2020](https://www.w3.org/TR/vc-di-eddsa/#the-ed25519signature2020-suite)
  * Verifier, Issuer
* :package: [VC HTTP API & Service](https://github.com/filip26/iron-vc-api)

## Installation

### Maven

Java 17+

```xml
<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-ed25519-cryptosuite-2020</artifactId>
    <version>0.14.0</version>
</dependency>

<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-verifiable-credentials</artifactId>
    <version>0.14.0</version>
</dependency>
```

### Gradle

Android 12+ (API Level >=31)

```gradle
implementation("com.apicatalog:iron-ed25519-cryptosuite-2020-jre8:0.14.0")
implementation("com.apicatalog:iron-verifiable-credentials-jre8:0.14.0")
```

## Usage

### Verifier

```javascript
// create a new verifier instance
static Verifier VERIFIER = Verifier.with(new Ed25519Signature2020())
    .loader(new Ed25519ContextLoader())
    // options
    .statusValidator(...)
    .subjectValidator(...);

try {
  // verify the given input proof(s)
  var verifiable = VERIFIER.verify(credential|presentation);
  
  // or with runtime parameters e.g. domain, challenge, etc.
  var verifiable = VERIFIER.verify(credential|presentation, parameters);
  
  // get verified details
  verifiable.subject()
  verifiable.id()
  verifiable.type()
  // ...
  
} catch (VerificationError | DocumentError e) {
  ...
}

```

### Issuer

```javascript
// create a signature suite static instance
static SignatureSuite SUITE = new Ed25519Signature2020();

// create a new issuer instance
Issuer ISSUER = SUITE.createIssuer(keyPairProvider)
    .loader(Ed25519ContextLoader());
    
try {
  // create a new proof draft
  var proofDraft = SUITE.createDraft(verificationMethod, purpose);
  // set custom options
  proofDraft.created(...);
  proofDraft.domain(...);
  ...

  // issue a new verifiable, i.e. sign the input and add a new proof
  var verifiable = ISSUER.sign(credential|presentation, proofDraft).compacted();
  
} catch (SigningError | DocumentError e) {
  ...
}

```

## Documentation

[![javadoc](https://javadoc.io/badge2/com.apicatalog/iron-ed25519-cryptosuite-2020/javadoc.svg)](https://javadoc.io/doc/com.apicatalog/iron-ed25519-cryptosuite-2020)

## Contributing

All PR's welcome!

### Building

Fork and clone the project repository.

#### Java 17
```bash
> cd iron-ed25519-cryptosuite-2020
> mvn clean package
```

#### Java 8
```bash
> cd iron-ed25519-cryptosuite-2020
> mvn -f pom_jre8.xml clean package
```

## Resources
* [Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa/)
* [Iron Verifiable Credentials](https://github.com/filip26/iron-verifiable-credentials)

## Sponsors

<a href="https://github.com/digitalbazaar">
  <img src="https://avatars.githubusercontent.com/u/167436?s=200&v=4" width="40" />
</a> 

## Commercial Support
Commercial support is available at filip26@gmail.com
