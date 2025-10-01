
package io.github.wistefan.dcql.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Pojo containing the structur of a claims-query {@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3}
 */
@Data
@NoArgsConstructor
public class ClaimsQuery {

	public ClaimsQuery(String id, List<Object> path, List<Object> values) {
		this.id = id;
		this.path = path;
		this.values = values;
	}

	/**
	 * REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise. A string identifying the
	 * particular claim. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-)
	 * characters. Within the particular claims array, the same id MUST NOT be present more than once.
	 */
	private String id;

	/**
	 * The value MUST be a non-empty array representing a claims path pointer that specifies the path to a claim within
	 * the Credential.
	 */
	private List<Object> path;

	/**
	 * A non-empty array of strings, integers or boolean values that specifies the expected values of the claim. If the
	 * values property is present, the Wallet SHOULD return the claim only if the type and value of the claim both match
	 * exactly for at least one of the elements in the array.
	 */
	private List<Object> values;

	// ---- MDoc Specific parameters ----

	/**
	 * MDoc specific parameter. The flag can be set to inform that the reader wishes to keep(store) the data. In case of
	 * false, its data is only used to be dispalyed and verified.
	 */
	private Boolean intent_to_retain;

	/**
	 * Refers to a namespace inside an mdoc
	 */
	private String namespace;

	/**
	 * Identifier for the data-element in the namespace
	 */
	private String claimName;
}
