# DCQL-Java

A Java implementation of the [Digital Credentials Query Language(DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l).

## Maven

The library is avaliable at maven central:

## Example usage

In order to evaluate DCQL-Queries, a list of [VerifiableCredentials](https://en.wikipedia.org/wiki/Verifiable_credentials) has to be provided.
The library itself uses a minimum of dependencies, therefor parsing of credentials and queries needs to be done by the caller.
A possible option is [Jackson](https://github.com/FasterXML/jackson). In order to properly deserialize a query, the [ObjectMapper](https://www.baeldung.com/jackson-object-mapper-tutorial)
needs to be configured as following:

```java
    ObjectMapper objectMapper = new ObjectMapper();
    // future and backwards compatible, just ignore unsupported parts
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    // properties should be translated following snake-case, e.g. `claimSet` becomes `claim_set`and vice versa
    objectMapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    SimpleModule deserializerModule = new SimpleModule();
    // help deserialization of the enums. See test/java/io/github/wistefan/dcql/helper for their implementations
    deserializerModule.addDeserializer(CredentialFormat.class, new CredentialFormatDeserializer());
    deserializerModule.addDeserializer(TrustedAuthorityType.class, new TrustedAuthorityTypeDeserializer());
    objectMapper.registerModule(deserializerModule);
```

Since credentials are usually not standard json-format, additional helper might be required. In case of sd-jwt and jwt credentials, 
a library like [Nimbus JOSE+JWT](https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt) can be used. See examples for loading SD and JWT credentials
in the [ParseCredentialTest](./src/test/java/io/github/wistefan/dcql/example/ParseCredentialTest.java)

After loading the credentials and providing query, evaluation is straight-forward:
```java
    // this configuration would support all CredentialFormats currently included in DCQL.
    DCQLEvaluator dcqlEvaluator = new DCQLEvaluator(List.of(
        new JwtCredentialEvaluator(),
        new DcSdJwtCredentialEvaluator(),
        new VcSdJwtCredentialEvaluator(),
        new MDocCredentialEvaluator(),
        new LdpCredentialEvaluator()));
    QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(dcqlQuery, credentialsList);
```

The [QueryResult](./src/main/java/io/github/wistefan/dcql/QueryResult.java) provides a quick success indicator and the filtered list of credentials to be used.
In case of SD-JWT Credentials, only the requested elements are disclosed.

## Limitations

As of now, DCQL-Java only supports querying for trusted authorities of type [Authority Key Identifier("aki")](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authority-key-identifier). 
In order to do so, a [bouncycastle](https://www.bouncycastle.org/) implementation needs to be provided:

```xml
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>${version.org.bouncycastle}</version>
    </dependency>
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcpkix-jdk18on</artifactId>
        <version>${version.org.bouncycastle}</version>
    </dependency>
```

## License

DCQL-Java is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

