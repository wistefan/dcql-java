package io.github.wistefan.dcql.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.wistefan.dcql.*;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.DcqlQuery;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.MDocCredential;
import io.github.wistefan.dcql.model.credential.MDocHeaders;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DcqlClaimSetQueryTest extends DcqlTest {


    private static final String MDOC_MVRC_QUERY = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "mso_mdoc",
                  "multiple": true,
                  "meta": { "doctype_value": "org.iso.7367.1.mVRC" },
                  "claims": [
                    { "id": "a", "namespace": "org.iso.7367.1", "claim_name": "vehicle_holder" },
                    { "id": "b", "namespace": "org.iso.18013.5.1", "claim_name": "first_name" },
                    { "id": "c", "namespace": "org.iso.18013.5.1", "claim_name": "first_name" }
                  ],
                  "claim_sets": [
                  	["b","c"],
                  	["a"]
                  ],
                  "require_cryptographic_holder_binding": false
                }
              ]
            }
            """;

    private static final String MDOC_MVRC_QUERY_SINGLE = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "mso_mdoc",
                  "multiple": false,
                  "meta": { "doctype_value": "org.iso.7367.1.mVRC" },
                  "claims": [
                    { "id": "a", "namespace": "org.iso.7367.1", "claim_name": "vehicle_holder" },
                    { "id": "b", "namespace": "org.iso.18013.5.1", "claim_name": "first_name" },
                    { "id": "c", "namespace": "org.iso.18013.5.1", "claim_name": "first_name" }
                  ],
                  "claim_sets": [
                  	["b","c"],
                  	["a"]
                  ],
                  "require_cryptographic_holder_binding": false
                }
              ]
            }
            """;

    private static final Credential MDOC_MVRC_FULL = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, new MDocHeaders(null, List.of(generateTestCertificate(TEST_KEY))), Map.of(
            "docType", "org.iso.7367.1.mVRC",
            "namespaces", Map.of(
                    "org.iso.7367.1", Map.of("vehicle_holder", "Martin Auer"),
                    "org.iso.18013.5.1", Map.of("first_name", "Martin", "last_name", "Auer")
            ),
            "authority", Map.of("type", "aki", "values", List.of("one")),
            "cryptographic_holder_binding", true
    )));

    private static final Credential MDOC_MVRC_HOLDER = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, new MDocHeaders(null, List.of(generateTestCertificate(TEST_KEY))), Map.of(
            "docType", "org.iso.7367.1.mVRC",
            "namespaces", Map.of(
                    "org.iso.7367.1", Map.of("vehicle_holder", "Martin Auer")
            ),
            "authority", Map.of("type", "aki", "values", List.of("one")),
            "cryptographic_holder_binding", true
    )));

    private static final Credential MDOC_MVRC_NAME = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, new MDocHeaders(null, List.of(generateTestCertificate(TEST_KEY))), Map.of(
            "docType", "org.iso.7367.1.mVRC",
            "namespaces", Map.of(
                    "org.iso.18013.5.1", Map.of("first_name", "Martin", "last_name", "Auer")
            ),
            "authority", Map.of("type", "aki", "values", List.of("one")),
            "cryptographic_holder_binding", true
    )));

    private static final Credential MDOC_MVRC_LAST_NAME = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, new MDocHeaders(null, List.of(generateTestCertificate(TEST_KEY))), Map.of(
            "docType", "org.iso.7367.1.mVRC",
            "namespaces", Map.of(
                    "org.iso.18013.5.1", Map.of("last_name", "Auer")
            ),
            "authority", Map.of("type", "aki", "values", List.of("one")),
            "cryptographic_holder_binding", true
    )));


    private static final String SD_JWT_QUERY_ADDRESS = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "vc+sd-jwt",
                  "meta": { "vct_values": ["https://credentials.example.com/identity_credential", "https://credentials.example.com/address_credential"] },
                  "claims": [
                    { "id": "a", "path": ["address","street_address"] },
                    { "id": "b", "path": ["street_address"] }
                  ],
                  "claim_sets": [
                  	["b"],
                  	["a"]
                  ],
                  "require_cryptographic_holder_binding": false
                }
              ]
            }
            """;

    private static final String SD_JWT_QUERY_ALTERNATIVES = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "vc+sd-jwt",
                  "meta": { "vct_values": ["https://credentials.example.com/identity_credential", "https://credentials.example.com/address_credential","https://credentials.example.com/name_credential"]  },
                  "claims": [
                    { "id": "a", "path": ["address","street_address"] },
                    { "id": "b", "path": ["street_address"] },
                    { "id": "c", "path": ["first_name"] },
                    { "id": "d", "path": ["last_name"] }
                  ],
                  "claim_sets": [
                  	["c","d"],
                  	["b"],
                  	["a"]
                  ],
                  "require_cryptographic_holder_binding": false
                }
              ]
            }
            """;
    private static final Credential SD_JWT_VC_FULL = new Credential(CredentialFormat.VC_SD_JWT,
            new SdJwtCredential(null,
                    new JwtCredential(null, null,
                            Map.of(
                                    "vct", "https://credentials.example.com/identity_credential",
                                    "name", Map.of("_sd", List.of(getDisclosure("salt-b", "first_name", "Arthur").getSdHash(), getDisclosure("salt-c", "last_name", "Dent").getSdHash())),
                                    "address", Map.of("_sd", List.of(getDisclosure("salt-a", "street_address", "42 Market Street").getSdHash(), "hash-x")),
                                    "cryptographic_holder_binding", false), null),
                    List.of(getDisclosure("salt-a", "street_address", "42 Market Street"),
                            getDisclosure("salt-b", "first_name", "Arthur"),
                            getDisclosure("salt-c", "last_name", "Dent"))
            ));

    private static final Credential SD_JWT_VC_ADDRESS = new Credential(CredentialFormat.VC_SD_JWT,
            new SdJwtCredential(null,
                    new JwtCredential(null, null,
                            Map.of(
                                    "vct", "https://credentials.example.com/address_credential",
                                    "_sd", List.of(
                                            getDisclosure("salt-a", "street_address", "42 Market Street")
                                                    .getSdHash(),
                                            "hash-x"),
                                    "cryptographic_holder_binding", false), null),
                    List.of(getDisclosure("salt-a", "street_address", "42 Market Street"))
            ));

    private static final Credential SD_JWT_VC_NAME = new Credential(CredentialFormat.VC_SD_JWT,
            new SdJwtCredential(null,
                    new JwtCredential(null, null,
                            Map.of(
                                    "vct", "https://credentials.example.com/name_credential",
                                    "_sd", List.of(
                                            getDisclosure("salt-b", "first_name", "Arthur").getSdHash(),
                                            getDisclosure("salt-c", "last_name", "Dent").getSdHash()),
                                    "cryptographic_holder_binding", false), null),
                    List.of(getDisclosure("salt-b", "first_name", "Arthur"),
                            getDisclosure("salt-c", "last_name", "Dent"))
            ));


    @Test
    @DisplayName("sd-jwt query get alternative")
    void sdJwtQueryGetAlternative() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(SD_JWT_QUERY_ALTERNATIVES, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(SD_JWT_VC_ADDRESS, SD_JWT_VC_FULL));

        assertTrue(queryResult.success());
        assertEquals(1, queryResult.credentials().get("credentials").size());
        Credential credential = queryResult.credentials().get("credentials").get(0);
        if (credential.getRawCredential() instanceof SdJwtCredential sdJwtCredential) {
            assertEquals(1, sdJwtCredential.getDisclosures().size());
        } else {
            fail("Did not get an SdJwt Credential.");
        }
    }


    @Test
    @DisplayName("sd-jwt query get for name")
    void sdJwtQueryForName() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(SD_JWT_QUERY_ALTERNATIVES, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(SD_JWT_VC_NAME, SD_JWT_VC_ADDRESS, SD_JWT_VC_FULL));

        assertTrue(queryResult.success());
        assertEquals(1, queryResult.credentials().get("credentials").size());
        Credential credential = queryResult.credentials().get("credentials").get(0);
        if (credential.getRawCredential() instanceof SdJwtCredential sdJwtCredential) {
            assertEquals(2, sdJwtCredential.getDisclosures().size());
        } else {
            fail("Did not get an SdJwt Credential.");
        }
    }

    @Test
    @DisplayName("sd-jwt query get for street_address within full")
    void sdJwtQueryForStreetAddressInFull() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(SD_JWT_QUERY_ADDRESS, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(SD_JWT_VC_NAME, SD_JWT_VC_FULL));

        assertTrue(queryResult.success());
        assertEquals(1, queryResult.credentials().get("credentials").size());
        Credential credential = queryResult.credentials().get("credentials").get(0);
        if (credential.getRawCredential() instanceof SdJwtCredential sdJwtCredential) {
            assertEquals(1, sdJwtCredential.getDisclosures().size());
        } else {
            fail("Did not get an SdJwt Credential.");
        }
    }

    @Test
    @DisplayName("sd-jwt query get for street_address")
    void sdJwtQueryForStreetAddress() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(SD_JWT_QUERY_ADDRESS, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(SD_JWT_VC_ADDRESS, SD_JWT_VC_NAME, SD_JWT_VC_FULL));

        assertTrue(queryResult.success());
        assertEquals(1, queryResult.credentials().get("credentials").size());
        Credential credential = queryResult.credentials().get("credentials").get(0);

        if (credential.getRawCredential() instanceof SdJwtCredential sdJwtCredential) {
            assertEquals(1, sdJwtCredential.getDisclosures().size());
        } else {
            fail("Did not get an SdJwt Credential.");
        }
    }

    @Test
    @DisplayName("mdoc mvrc query get full doc")
    void mdocMvrcQueryFullDocSet() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC_FULL, MDOC_MVRC_HOLDER));
        assertTrue(queryResult.success());
        assertEquals(1, queryResult.credentials().get("credentials").size());
        Credential credential = queryResult.credentials().get("credentials").get(0);
        assertEquals(credential, MDOC_MVRC_FULL);
    }

    @Test
    @DisplayName("mdoc mvrc query get second set")
    void mdocMvrcQuerySecondSet() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC_LAST_NAME, MDOC_MVRC_HOLDER));

        assertTrue(queryResult.success());
        assertEquals(1, queryResult.credentials().get("credentials").size());
        Credential credential = queryResult.credentials().get("credentials").get(0);
        assertEquals(credential, MDOC_MVRC_HOLDER);
    }

    @Test
    @DisplayName("mdoc mvrc query gets the fullfilling credentials.")
    void mdocMvrcQueryOnlyOne() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC_LAST_NAME, MDOC_MVRC_HOLDER, MDOC_MVRC_NAME, MDOC_MVRC_FULL));

        assertTrue(queryResult.success());
        assertEquals(2, queryResult.credentials().get("credentials").size());
        List<Credential> credentials = queryResult.credentials().get("credentials");
        assertTrue(credentials.contains(MDOC_MVRC_NAME));
        assertTrue(credentials.contains(MDOC_MVRC_FULL));
    }

    @Test
    @DisplayName("mdoc mvrc query fails when multiple credentials match, but multiple is not allowed.")
    void mdocMvrcQueryFailedMultiple() throws JsonProcessingException {
        var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY_SINGLE, DcqlQuery.class);
        QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC_LAST_NAME, MDOC_MVRC_HOLDER, MDOC_MVRC_NAME, MDOC_MVRC_FULL));

        assertFalse(queryResult.success());
    }
}
