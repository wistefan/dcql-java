
package io.github.wistefan.dcql.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.wistefan.dcql.DCQLEvaluator;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.DcqlQuery;
import io.github.wistefan.dcql.model.credential.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DcqlQueryTest extends DcqlTest {

	private static final String MDOC_MVRC_QUERY = "{\n" +
			"  \"credentials\": [\n" +
			"    {\n" +
			"      \"id\": \"my_credential\",\n" +
			"      \"format\": \"mso_mdoc\",\n" +
			"      \"meta\": { \"doctype_value\": \"org.iso.7367.1.mVRC\" },\n" +
			"      \"require_cryptographic_holder_binding\": true,\n" +
			"      \"claims\": [\n" +
			"        { \"path\": [\"org.iso.7367.1\", \"vehicle_holder\"], \"intent_to_retain\": false },\n" +
			"        { \"path\": [\"org.iso.18013.5.1\", \"first_name\"], \"intent_to_retain\": true }\n" +
			"      ],\n" +
			"      \"trusted_authorities\": [\n" +
			"        { \"type\": \"aki\", \"values\": [\"" + Base64.getUrlEncoder().encodeToString(generateTestAki(TEST_KEY).getKeyIdentifier()) + "\"] }\n" +
			"      ]\n" +
			"    }\n" +
			"  ]\n" +
			"}";

	private static final String MDOC_NAMESPACE_MVRC_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "my_credential",
			      "format": "mso_mdoc",
			      "meta": { "doctype_value": "org.iso.7367.1.mVRC" },
			      "claims": [
			        { "namespace": "org.iso.7367.1", "claim_name": "vehicle_holder" },
			        { "namespace": "org.iso.18013.5.1", "claim_name": "first_name" }
			      ],
			      "require_cryptographic_holder_binding": false
			    }
			  ]
			}
			""";

	private static final Credential MDOC_MVRC = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(new MDocHeaders(null, List.of(generateTestCertificate(TEST_KEY))), Map.of(
			"docType", "org.iso.7367.1.mVRC",
			"namespaces", Map.of(
					"org.iso.7367.1", Map.of("vehicle_holder", "Martin Auer"),
					"org.iso.18013.5.1", Map.of("first_name", "Martin Auer")
			),
			"authority", Map.of("type", "aki", "values", List.of("one")),
			"cryptographic_holder_binding", true
	)));

	private static final Credential EXAMPLE_MDOC = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, Map.of(
			"docType", "example_doctype",
			"namespaces", Map.of("example_namespaces", Map.of("example_claim", "example_value")),
			"authority", Map.of("type", "aki", "values", List.of("something")),
			"cryptographic_holder_binding", true
	)));

	private static final Credential EXAMPLE_SD_JWT_VC = new Credential(CredentialFormat.VC_SD_JWT,
			new SdJwtCredential(
					new JwtCredential(null,
							Map.of(
									"vct", "https://credentials.example.com/identity_credential",
									"_sd", List.of("hash-b", "hash-c"),
									"address", Map.of("_sd", List.of("hash-a", "hash-x")),
									"cryptographic_holder_binding", false), null),
					List.of(new Disclosure("hash-a", "street_address", "42 Market Street"),
							new Disclosure("hash-b", "first_name", "Arthur"),
							new Disclosure("hash-c", "last_name", "Dent"))
			));

	private static final Credential EXAMPLE_W3C_LDP_VC = new Credential(CredentialFormat.LDP_VC, new LdpCredential(Map.of(
			"type", List.of("https://www.w3.org/2018/credentials#VerifiableCredential", "https://example.org/examples#AlumniCredential", "https://example.org/examples#BachelorDegree"),
			"credentialSubject", Map.of("first_name", "Arthur", "last_name", "Dent", "address", Map.of("street_address", "42 Market Street")),
			"cryptographic_holder_binding", false
	)));


	private static final String SD_JWT_VC_EXAMPLE_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "my_credential",
			      "format": "vc+sd-jwt",
			      "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
			      "claims": [ { "path": ["last_name"] }, { "path": ["first_name"] }, { "path": ["address", "street_address"] } ],
			      "require_cryptographic_holder_binding": false
			    }
			  ]
			}
			""";

	private static final String SD_JWT_VC_MULTIPLE_EXAMPLE_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "my_credential",
			      "format": "vc+sd-jwt",
			      "multiple": true,
			      "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
			      "claims": [ { "path": ["last_name"] }, { "path": ["first_name"] }, { "path": ["address", "street_address"] } ],
			      "require_cryptographic_holder_binding": false
			    }
			  ]
			}
			""";

	private static final String SD_JWT_VC_NO_CLAIMS_EXAMPLE_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "my_credential",
			      "format": "vc+sd-jwt",
			      "multiple": true,
			      "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
			      "require_cryptographic_holder_binding": false
			    }
			  ]
			}
			""";

	private static final String W3C_LDP_VC_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "my_credential",
			      "format": "ldp_vc",
			      "meta": {
			        "type_values": [
			          ["https://example.org/examples#AlumniCredential", "https://example.org/examples#BachelorDegree"],
			          ["https://www.w3.org/2018/credentials#VerifiableCredential", "https://example.org/examples#UniversityDegreeCredential"]
			        ]
			      },
			      "claims": [ { "path": ["credentialSubject", "last_name"] }, { "path": ["credentialSubject", "first_name"] }, { "path": ["credentialSubject", "address", "street_address"] } ],
			      "require_cryptographic_holder_binding": false
			    }
			  ]
			}
			""";


	@Test
	@DisplayName("mdoc mvrc query fails with invalid mdoc")
	void mdocMvrcQueryFailsWithInvalidMdoc() throws JsonProcessingException {
		var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(EXAMPLE_MDOC));

		assertEquals(0, credentialsResult.size());
	}

	@Test
	@DisplayName("mdoc mvrc example with multiple credentials succeeds")
	void mdocMvrcExampleWithMultipleCredentialsSucceeds() throws JsonProcessingException {
		var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(EXAMPLE_MDOC, MDOC_MVRC));

		assertEquals(1, credentialsResult.size());
		assertEquals(MDOC_MVRC, credentialsResult.get(0));
	}

	@Test
	@DisplayName("w3cLdpVc example succeeds")
	void w3cLdpVcExampleSucceeds() throws JsonProcessingException {
		var query = OBJECT_MAPPER.readValue(W3C_LDP_VC_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(EXAMPLE_W3C_LDP_VC));

		assertEquals(1, credentialsResult.size());
	}

	@Test
	@DisplayName("w3cLdpVc query fails with invalid type values")
	void w3cLdpVcQueryFailsWithInvalidTypeValues() throws JsonProcessingException {
		var query = OBJECT_MAPPER.readValue(W3C_LDP_VC_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC));

		assertTrue(credentialsResult.isEmpty());
	}

	@Test
	@DisplayName("mdocMvrc example using namespaces succeeds")
	void mdocMvrcExampleUsingNamespacesSucceeds() throws JsonProcessingException {
		var query = OBJECT_MAPPER.readValue(MDOC_NAMESPACE_MVRC_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MVRC));

		assertEquals(1, credentialsResult.size());
	}

	@Test
	@DisplayName("sdJwtVc example with multiple credentials succeeds")
	void sdJwtVcExampleWithMultipleCredentialsSucceeds() throws JsonProcessingException {

		var query = OBJECT_MAPPER.readValue(SD_JWT_VC_EXAMPLE_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(EXAMPLE_MDOC, EXAMPLE_SD_JWT_VC));

		assertFalse(credentialsResult.isEmpty());
		assertEquals(1, credentialsResult.size());
		Credential theCredential = credentialsResult.get(0);
		assertEquals(CredentialFormat.VC_SD_JWT, theCredential.getCredentialFormat());
		if (theCredential.getRawCredential() instanceof SdJwtCredential sdJwtCredential) {
			assertEquals(3, sdJwtCredential.getDisclosures().size());
		} else {
			fail("It should be an SD-JWT credential.");
		}
	}

	@Test
	@DisplayName("sdJwtVc with 'multiple' set to true succeeds")
	void sdJwtVcWithMultipleSetToTrueSucceeds() throws JsonProcessingException {

		var query = OBJECT_MAPPER.readValue(SD_JWT_VC_MULTIPLE_EXAMPLE_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(EXAMPLE_SD_JWT_VC, EXAMPLE_SD_JWT_VC));
		assertEquals(2, credentialsResult.size());
	}

	@Test
	@DisplayName("sdJwtVc with 'multiple' set to true but only one credential in the presentation matches")
	void sdJwtVcWithMultipleButOneMatch() throws JsonProcessingException {

		var query = OBJECT_MAPPER.readValue(SD_JWT_VC_MULTIPLE_EXAMPLE_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(EXAMPLE_SD_JWT_VC, EXAMPLE_MDOC));

		assertEquals(1, credentialsResult.size());
		assertEquals(CredentialFormat.VC_SD_JWT, credentialsResult.get(0).getCredentialFormat());
		if (credentialsResult.get(0).getRawCredential() instanceof SdJwtCredential sdJwtCredential) {
			assertEquals(3, sdJwtCredential.getDisclosures().size());
		} else {
			fail("An SdJwtCredential should be contained.");
		}
	}

	@Test
	@DisplayName("sdJwtVc with no claims should not disclose anything.")
	void sdJwtVcWithNoClaims() throws JsonProcessingException {

		var query = OBJECT_MAPPER.readValue(SD_JWT_VC_NO_CLAIMS_EXAMPLE_QUERY, DcqlQuery.class);
		List<Credential> credentialsResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(EXAMPLE_SD_JWT_VC, EXAMPLE_MDOC));

		assertEquals(1, credentialsResult.size());
		assertEquals(CredentialFormat.VC_SD_JWT, credentialsResult.get(0).getCredentialFormat());
		if (credentialsResult.get(0).getRawCredential() instanceof SdJwtCredential sdJwtCredential) {
			assertTrue(sdJwtCredential.getDisclosures().isEmpty());
		} else {
			fail("An SdJwtCredential should be contained.");
		}
	}

}
