
package io.github.wistefan.dcql.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.wistefan.dcql.DCQLEvaluator;
import io.github.wistefan.dcql.QueryResult;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.DcqlQuery;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.MDocCredential;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DcqlQueryComplexTest extends DcqlTest {

	// --- Test Data ---

	private static final String COMPLEX_MDOC_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "mdl-id",
			      "format": "mso_mdoc",
			      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
			      "claims": [
			        { "id": "given_name", "namespace": "org.iso.18013.5.1", "claim_name": "given_name" },
			        { "id": "family_name", "namespace": "org.iso.18013.5.1", "claim_name": "family_name" },
			        { "id": "portrait", "namespace": "org.iso.18013.5.1", "claim_name": "portrait" }
			      ]
			    },
			    {
			      "id": "mdl-address",
			      "format": "mso_mdoc",
			      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
			      "claims": [
			        { "id": "resident_address", "path": ["org.iso.18013.5.1", "resident_address"], "intent_to_retain": false },
			        { "id": "resident_country", "path": ["org.iso.18013.5.1", "resident_country"], "intent_to_retain": true }
			      ]
			    },
			    {
			      "id": "photo_card-id",
			      "format": "mso_mdoc",
			      "meta": { "doctype_value": "org.iso.23220.photoid.1" },
			      "claims": [
			        { "id": "given_name", "path": ["org.iso.23220.1", "given_name"] },
			        { "id": "family_name", "path": ["org.iso.23220.1", "family_name"] },
			        { "id": "portrait", "path": ["org.iso.23220.1", "portrait"] }
			      ]
			    },
			    {
			      "id": "photo_card-address",
			      "format": "mso_mdoc",
			      "meta": { "doctype_value": "org.iso.23220.photoid.1" },
			      "claims": [
			        { "id": "resident_address", "path": ["org.iso.23220.1", "resident_address"] },
			        { "id": "resident_country", "path": ["org.iso.23220.1", "resident_country"] }
			      ]
			    }
			  ],
			  "credential_sets": [
			    { "purpose": "Identification", "options": [["mdl-id"], ["photo_card-id"]] },
			    { "purpose": "Proof of address", "required": false, "options": [["mdl-address"], ["photo_card-address"]] }
			  ]
			}
			""";

	private static final Credential MDOC_MDL_ID = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, Map.of(
			"credential_format", "mso_mdoc",
			"docType", "org.iso.18013.5.1.mDL",
			"namespaces", Map.of("org.iso.18013.5.1", Map.of("given_name", "Martin", "family_name", "Auer", "portrait", "https://example.com/portrait")),
			"cryptographic_holder_binding", true
	)));

	private static final Credential MDOC_MDL_ADDRESS = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, Map.of(
			"credential_format", "mso_mdoc",
			"docType", "org.iso.18013.5.1.mDL",
			"namespaces", Map.of("org.iso.18013.5.1", Map.of("resident_country", "Italy", "resident_address", "Via Roma 1", "non_disclosed", "secret")),
			"cryptographic_holder_binding", true
	)));

	private static final Credential MDOC_PHOTO_CARD_ID = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, Map.of(
			"credential_format", "mso_mdoc",
			"docType", "org.iso.23220.photoid.1",
			"namespaces", Map.of("org.iso.23220.1", Map.of("given_name", "Martin", "family_name", "Auer", "portrait", "https://example.com/portrait")),
			"cryptographic_holder_binding", true
	)));

	private static final Credential MDOC_PHOTO_CARD_ADDRESS = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, Map.of(
			"credential_format", "mso_mdoc",
			"docType", "org.iso.23220.photoid.1",
			"namespaces", Map.of("org.iso.23220.1", Map.of("resident_country", "Italy", "resident_address", "Via Roma 1", "non_disclosed", "secret")),
			"cryptographic_holder_binding", true
	)));

	private static final Credential MDOC_EXAMPLE = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, Map.of(
			"credential_format", "mso_mdoc",
			"docType", "example_doctype",
			"namespaces", Map.of("example_namespaces", Map.of("example_claim", "example_value")),
			"cryptographic_holder_binding", true
	)));

	private static final Credential SD_JWT_VC_EXAMPLE = new Credential(CredentialFormat.VC_SD_JWT, new SdJwtCredential(
			new JwtCredential(null, Map.of(
					"credential_format", "vc+sd-jwt",
					"vct", "https://credentials.example.com/identity_credential",
					"claims", Map.of(
							"first_name", "Arthur",
							"last_name", "Dent",
							"address", Map.of("street_address", "42 Market Street", "locality", "Milliways", "postal_code", "12345"),
							"degrees", List.of(
									Map.of("type", "Bachelor of Science", "university", "University of Betelgeuse"),
									Map.of("type", "Master of Science", "university", "University of Betelgeuse")
							),
							"nationalities", List.of("British", "Betelgeusian")
					),
					"cryptographic_holder_binding", true
			), null), List.of()));


	@Test
	@DisplayName("fails with no credentials")
	void failsWithNoCredentials() throws JsonProcessingException {

		var query = OBJECT_MAPPER.readValue(COMPLEX_MDOC_QUERY, DcqlQuery.class);
		QueryResult queryResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of());

		assertFalse(queryResult.success());
	}

	@Test
	@DisplayName("fails with credentials that do not satisfy a required claim_set")
	void failsWithCredentialsThatDoNotSatisfyARequiredClaimSet() throws JsonProcessingException {

		var query = OBJECT_MAPPER.readValue(COMPLEX_MDOC_QUERY, DcqlQuery.class);
		QueryResult queryResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(MDOC_MDL_ADDRESS, MDOC_PHOTO_CARD_ADDRESS));

		assertFalse(queryResult.success());
	}

	@Test
	@DisplayName("return the requested sets")
	void succeedsWithRequestedSets() throws JsonProcessingException {
		List<Credential> expectedIdCredentials = List.of(MDOC_MDL_ID);
		List<Credential> expectedPoaCredentials = List.of(MDOC_MDL_ADDRESS);

		var query = OBJECT_MAPPER.readValue(COMPLEX_MDOC_QUERY, DcqlQuery.class);
		QueryResult queryResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(
				MDOC_MDL_ID,
				MDOC_MDL_ADDRESS,
				MDOC_PHOTO_CARD_ID,
				MDOC_PHOTO_CARD_ADDRESS,
				MDOC_EXAMPLE,
				SD_JWT_VC_EXAMPLE));

		assertTrue(queryResult.success());
		assertTrue(queryResult.credentials().containsKey("Identification"));
		assertTrue(queryResult.credentials().containsKey("Proof of address"));

		List<Credential> identification = queryResult.credentials().get("Identification");
		List<Credential> poa = queryResult.credentials().get("Proof of address");

		assertEquals(1, identification.size());
		assertEquals(1, poa.size());

		expectedIdCredentials.forEach(
				ec -> assertTrue(identification.contains(ec)));
		expectedPoaCredentials.forEach(
				ec -> assertTrue(poa.contains(ec)));
	}

	@Test
	@DisplayName("return alternative if not included")
	void returnAlternative() throws JsonProcessingException {
		List<Credential> expectedIdCredentials = List.of(MDOC_PHOTO_CARD_ID);
		List<Credential> expectedPoaCredentials = List.of(MDOC_MDL_ADDRESS);

		var query = OBJECT_MAPPER.readValue(COMPLEX_MDOC_QUERY, DcqlQuery.class);
		QueryResult queryResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(
				MDOC_MDL_ADDRESS,
				MDOC_PHOTO_CARD_ID,
				MDOC_PHOTO_CARD_ADDRESS,
				MDOC_EXAMPLE,
				SD_JWT_VC_EXAMPLE));

		assertTrue(queryResult.success());
		assertTrue(queryResult.credentials().containsKey("Identification"));
		assertTrue(queryResult.credentials().containsKey("Proof of address"));

		List<Credential> identification = queryResult.credentials().get("Identification");
		List<Credential> poa = queryResult.credentials().get("Proof of address");

		assertEquals(1, identification.size());
		assertEquals(1, poa.size());

		expectedIdCredentials.forEach(
				ec -> assertTrue(identification.contains(ec)));
		expectedPoaCredentials.forEach(
				ec -> assertTrue(poa.contains(ec)));
	}

}
