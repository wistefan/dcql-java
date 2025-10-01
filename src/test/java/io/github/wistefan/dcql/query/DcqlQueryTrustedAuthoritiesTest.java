
package io.github.wistefan.dcql.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.wistefan.dcql.QueryResult;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.DcqlQuery;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.MDocCredential;
import io.github.wistefan.dcql.model.credential.MDocHeaders;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DcqlQueryTrustedAuthoritiesTest extends DcqlTest {


    // --- Test Data ---

    private static final Map<String, Object> ETSI_TL_AUTHORITY = Map.of("type", "etsi_tl", "values", List.of("https://list.com"));
    private static final Map<String, Object> OPENID_FEDERATION_AUTHORITY = Map.of("type", "openid_federation", "values", List.of("https://federation.com"));


    private static final String MDOC_MVRC_QUERY = "{\n" +
            "  \"credentials\": [\n" +
            "    {\n" +
            "      \"id\": \"my_credential\",\n" +
            "      \"format\": \"mso_mdoc\",\n" +
            "      \"trusted_authorities\": [\n" +
            "        {\n" +
            "          \"type\": \"aki\",\n" +
            "          \"values\": [\"" + Base64.getUrlEncoder().encodeToString(generateTestAki(TEST_KEY).getKeyIdentifier()) + "\", \"UVVJUkVELiBBIHN0cmluZyB1bmlxdWVseSBpZGVudGlmeWluZyB0aGUgdHlwZSA\"]\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  ]\n" +
            "}";

    private static final Credential MDOC_MVRC = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential( null, new MDocHeaders(null, List.of(generateTestCertificate(TEST_KEY))), Map.of(
            "credential_format", "mso_mdoc",
            "doctype", "org.iso.7367.1.mVRC",
            "namespaces", Map.of(
                    "org.iso.7367.1", Map.of("vehicle_holder", "Martin Auer", "non_disclosed", "secret"),
                    "org.iso.18013.5.1", Map.of("first_name", "Martin Auer")
            ),
            "cryptographic_holder_binding", true
    )));

    private static final Credential MDOC_MVRC_ALT_AKI = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential( null, new MDocHeaders(null, List.of(generateTestCertificate(generateTestKeyPair()))), Map.of(
            "credential_format", "mso_mdoc",
            "doctype", "org.iso.7367.1.mVRC",
            "namespaces", Map.of(
                    "org.iso.7367.1", Map.of("vehicle_holder", "Martin Auer", "non_disclosed", "secret"),
                    "org.iso.18013.5.1", Map.of("first_name", "Martin Auer")
            ),
            "cryptographic_holder_binding", true
    )));

    private static final Credential MDOC_MVRC_NO_X5C = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential( null, new MDocHeaders(null, List.of()), Map.of(
            "credential_format", "mso_mdoc",
            "doctype", "org.iso.7367.1.mVRC",
            "namespaces", Map.of(
                    "org.iso.7367.1", Map.of("vehicle_holder", "Martin Auer", "non_disclosed", "secret"),
                    "org.iso.18013.5.1", Map.of("first_name", "Martin Auer")
            ),
            "cryptographic_holder_binding", true
    )));

    private static final String SD_JWT_VC_EXAMPLE_QUERY = "{\n" +
            "  \"credentials\": [\n" +
            "    {\n" +
            "      \"id\": \"my_credential\",\n" +
            "      \"format\": \"vc+sd-jwt\",\n" +
            "      \"trusted_authorities\": [\n" +
            "        {\n" +
            "          \"type\": \"aki\",\n" +
            "          \"values\": [\"" + Base64.getUrlEncoder().encodeToString(generateTestAki(TEST_KEY).getKeyIdentifier()) + "\"]\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  ]\n" +
            "}";

    private static final Credential SD_JWT_VC = new Credential(CredentialFormat.VC_SD_JWT, new SdJwtCredential( null, new JwtCredential( null, Map.of("x5c", List.of(generateTestCertificate(TEST_KEY))), Map.of(
            "credential_format", "vc+sd-jwt",
            "vct", "https://credentials.example.com/identity_credential",
            "claims", Map.of("first_name", "Arthur", "last_name", "Dent"),
            "cryptographic_holder_binding", true
    ), null), List.of()));


    @Test
    @DisplayName("mdocMvrc example with trusted_authorities succeeds")
    void mdocMvrcExampleWithTrustedAuthoritiesSucceeds() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
        QueryResult credentialsResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC));

        assertTrue(credentialsResult.success());
        assertEquals(1, credentialsResult.credentials().get("credentials").size());
    }

    @Test
    @DisplayName("mdocMvrc example where authority does not match trusted_authorities entry")
    void mdocMvrcExampleWhereAuthorityDoesNotMatch() throws JsonProcessingException {

        var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
        QueryResult credentialsResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC_ALT_AKI));

        assertFalse(credentialsResult.success());
    }

    @Test
    @DisplayName("mdocMvrc example where trusted_authorities is present but no authority")
    void mdocMvrcExampleWithNoAuthority() throws JsonProcessingException {

        var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
        QueryResult credentialsResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC_NO_X5C));

        assertFalse(credentialsResult.success());
    }

    @Test
    @DisplayName("sdJwtVc example with trusted_authorities succeeds")
    void sdJwtVcExampleWithTrustedAuthoritiesSucceeds() throws JsonProcessingException {

        var query = OBJECT_MAPPER.readValue(SD_JWT_VC_EXAMPLE_QUERY, DcqlQuery.class);
        QueryResult credentialsResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(SD_JWT_VC));

        assertTrue(credentialsResult.success());
        assertEquals(1, credentialsResult.credentials().get("credentials").size());
    }

}
