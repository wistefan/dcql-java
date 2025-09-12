
package io.github.wistefan.dcql.model;

import lombok.Data;

import java.util.List;

/**
 * A Credential Set Query is an object representing a request for one or more Credentials to satisfy a particular use
 * case with the Verifier.
 */
@Data
public class CredentialSetQuery {

	/**
	 * A non-empty array, where each value in the array is a list of Credential Query identifiers representing one set
	 * of Credentials that satisfies the use case. The value of each element in the options array is a non-empty array
	 * of identifiers which reference elements in credentials.
	 */
	private List<List<String>> options;

	/**
	 * A boolean which indicates whether this set of Credentials is required to satisfy the particular use case at the
	 * Verifier.
	 */
	private Boolean required = true;

	/**
	 * A string, number or object specifying the purpose of the query. This specification does not define a specific
	 * structure or specific values for this property. The purpose is intended to be used by the Verifier to communicate
	 * the reason for the query to the Wallet. The Wallet MAY use this information to show the user the reason for the
	 * request.
	 */
	private Object purpose;
}