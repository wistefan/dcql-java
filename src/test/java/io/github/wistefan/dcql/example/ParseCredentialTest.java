package io.github.wistefan.dcql.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.credential.Disclosure;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class ParseCredentialTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    public void readJwtCredential() throws Exception {
        String jwtPath = "example/userCredential.jwt";
        String rawContent = loadFromFile(jwtPath);
        SignedJWT signedJWT = SignedJWT.parse(rawContent);
        assertDoesNotThrow(() -> {
            JwtCredential jwtCredential = new JwtCredential(rawContent, signedJWT.getHeader().toJSONObject(), signedJWT.getJWTClaimsSet().toJSONObject(), signedJWT.getSignature().decodeToString());
            new Credential(CredentialFormat.JWT_VC_JSON, jwtCredential);
        });
    }

    @Test
    public void readSdJwtCredential() throws Exception {
        String sdJwtPath = "example/legalPerson.sd_jwt";
        String rawContent = loadFromFile(sdJwtPath);

        assertDoesNotThrow(() -> {
            // split by disclosure separator
            String[] sdParts = rawContent.split("~");
            // parse the plain JWT
            SignedJWT signedJWT = SignedJWT.parse(sdParts[0]);
            Object algorithmClaim = signedJWT.getJWTClaimsSet().getClaim("_sd_alg");

            // decode the disclosures
            List<Disclosure> disclosures = Arrays.asList(sdParts)
                    // everything after the first element
                    .subList(1, sdParts.length)
                    .stream()
                    .map(disclosure -> {
                        try {
                            return toDisclosure(disclosure, algorithmClaim);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .toList();
            SdJwtCredential sdJwtCredential = new SdJwtCredential(rawContent,
                    new JwtCredential(rawContent, signedJWT.getHeader().toJSONObject(), signedJWT.getJWTClaimsSet().toJSONObject(), signedJWT.getSignature().decodeToString()),
                    disclosures);
        });
    }

    private static String loadFromFile(String path) throws IOException {
        try (InputStream is = ParseCredentialTest.class.getClassLoader().getResourceAsStream(path)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + path);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }


    // decode the encoded disclosure
    private Disclosure toDisclosure(String encoded, Object sdAlgorithm) throws IOException {
        byte[] sdBytes = Base64.getUrlDecoder().decode(encoded);
        List<?> sdContents = OBJECT_MAPPER.readValue(sdBytes, List.class);
        String salt = null;
        String claim = null;
        if (sdContents.get(0) instanceof String saltElement) {
            salt = saltElement;
        }
        if (sdContents.get(1) instanceof String claimElement) {
            claim = claimElement;
        }
        if (sdAlgorithm instanceof String sdAlgorithmString) {
            return new Disclosure(salt, claim, sdContents.get(2), encoded, sdAlgorithmString);
        }
        throw new IllegalArgumentException("Was not able to create disclosure.");
    }
}
