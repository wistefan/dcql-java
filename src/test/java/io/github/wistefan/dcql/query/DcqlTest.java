package io.github.wistefan.dcql.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.github.wistefan.dcql.helper.CredentialFormatDeserializer;
import io.github.wistefan.dcql.helper.TrustedAuthorityTypeDeserializer;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.TrustedAuthorityType;
import io.github.wistefan.dcql.model.credential.Disclosure;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public abstract class DcqlTest {

    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    {
        OBJECT_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        OBJECT_MAPPER.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        SimpleModule deserializerModule = new SimpleModule();
        deserializerModule.addDeserializer(CredentialFormat.class, new CredentialFormatDeserializer());
        deserializerModule.addDeserializer(TrustedAuthorityType.class, new TrustedAuthorityTypeDeserializer());
        OBJECT_MAPPER.registerModule(deserializerModule);
    }

    public static final KeyPair TEST_KEY = generateTestKeyPair();


    public static KeyPair generateTestKeyPair() {
        try {
            // Generate keypair
            KeyPairGenerator keyGen = null;

            keyGen = KeyPairGenerator.getInstance("RSA");

            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static AuthorityKeyIdentifier generateTestAki(KeyPair testKey) {

        Security.addProvider(new BouncyCastleProvider());
        try {
            X509ExtensionUtils extUtils = new X509ExtensionUtils(
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider("BC")
                            .build()
                            .get(new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1))
            );

            // Now you can create SKI and AKI
            SubjectPublicKeyInfo subjectPublicKeyInfo =
                    SubjectPublicKeyInfo.getInstance(testKey.getPublic().getEncoded());

            return extUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


    public static X509Certificate generateTestCertificate(KeyPair testKey) {

        Security.addProvider(new BouncyCastleProvider());
        try {
            Security.addProvider(new BouncyCastleProvider());
            // Certificate details
            String issuer = "CN=Test CA";
            String subject = "CN=Test Cert";
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
            Date notAfter = new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365));

            // Builder
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    new javax.security.auth.x500.X500Principal(issuer),
                    serial,
                    notBefore,
                    notAfter,
                    new javax.security.auth.x500.X500Principal(subject),
                    testKey.getPublic()
            );
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false, generateTestAki(testKey));
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .build(testKey.getPrivate());
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certBuilder.build(signer));
            return cert;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Disclosure getDisclosure(String salt, String claim, Object value) {
        try {
            byte[] encoded = new ObjectMapper().writeValueAsBytes(List.of(salt, claim, value));
            return new Disclosure(salt, claim, value, Base64.getUrlEncoder().encodeToString(encoded), "sha-256");
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
