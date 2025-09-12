
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DcqlQueryWithJsonTransformTest extends DcqlTest {

	/**
	 * A placeholder for a class that might be used in credential data and needs special handling,
	 * similar to the ValueClass in the TypeScript test.
	 */
	static class ValueClass {
		private final Object value;

		public ValueClass(Object value) {
			this.value = value;
		}

		public Object toJson() {
			return this.value;
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof ValueClass && ((ValueClass) o).value.equals(this.value);
		}

		@Override
		public int hashCode() {
			return value.hashCode();
		}
	}

	// --- Test Data ---

	private static final String MDOC_MVRC_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "my_credential",
			      "format": "mso_mdoc",
			      "meta": { "doctype_value": "org.iso.7367.1.mVRC" },
			      "claims": [
			        { "namespace": "org.iso.7367.1", "claim_name": "vehicle_holder" },
			        { "namespace": "org.iso.18013.5.1", "claim_name": "first_name" }
			      ]
			    }
			  ]
			}
			""";

	private static final String SD_JWT_VC_EXAMPLE_QUERY = """
			{
			  "credentials": [
			    {
			      "id": "my_credential",
			      "format": "dc+sd-jwt",
			      "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
			      "claims": [
			        { "path": ["last_name"] },
			        { "path": ["first_name"] },
			        { "path": ["address", "street_address"] },
			        { "path": ["org.iso.7367.1", "vehicle_holder"], "values": ["Timo Glastra"] }
			      ]
			    }
			  ]
			}
			""";

	private static final Credential MDOC_WITH_JT = new Credential(CredentialFormat.MSO_MDOC, new MDocCredential(null, Map.of(
			"docType", "org.iso.7367.1.mVRC",
			"namespaces", Map.of(
					"org.iso.7367.1", Map.of("vehicle_holder", "Martin Auer", "non_disclosed", "secret"),
					"org.iso.18013.5.1", Map.of("first_name", new ValueClass("Martin Auer"))
			),
			"cryptographic_holder_binding", true
	)));

	private static final Credential SD_JWT_VC_WITH_JT = new Credential(CredentialFormat.DC_SD_JWT,
			new SdJwtCredential(
					new JwtCredential(null, Map.of(
							"vct", "https://credentials.example.com/identity_credential",
							"claims", Map.of(
									"first_name", "Arthur",
									"last_name", "Dent",
									"address", Map.of("street_address", new ValueClass("42 Market Street"), "locality", "Milliways", "postal_code", "12345"),
									"org.iso.7367.1", Map.of("vehicle_holder", "Timo Glastra")
							),
							"cryptographic_holder_binding", true
					), null), List.of()));

	@Test
	@DisplayName("mdocMvrc example succeeds")
	void mdocMvrcExampleSucceeds() throws JsonProcessingException {
		var query = OBJECT_MAPPER.readValue(MDOC_MVRC_QUERY, DcqlQuery.class);
		QueryResult queryResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(MDOC_WITH_JT));

		assertTrue(queryResult.success());
		assertEquals(1, queryResult.credentials().get("credentials").size());
	}

	@Test
	@DisplayName("sdJwtVc example with multiple credentials succeeds")
	void sdJwtVcExampleWithMultipleCredentialsSucceeds() throws JsonProcessingException {
		var query = OBJECT_MAPPER.readValue(SD_JWT_VC_EXAMPLE_QUERY, DcqlQuery.class);
		QueryResult queryResult = DCQLEvaluator.evaluateDCQLQuery(query, List.of(MDOC_WITH_JT, SD_JWT_VC_WITH_JT));

		assertTrue(queryResult.success());
		assertEquals(1, queryResult.credentials().get("credentials").size());
		assertEquals(CredentialFormat.DC_SD_JWT, queryResult.credentials().get("credentials").get(0).getCredentialFormat());
	}

}
