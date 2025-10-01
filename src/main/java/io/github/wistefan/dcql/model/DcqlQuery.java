
package io.github.wistefan.dcql.model;

import lombok.Data;

import java.util.List;

/**
 * A JSON-encoded query that allows the Verifier to request presentations that match the query.
 * {@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l}
 */
@Data
public class DcqlQuery {

	/**
	 * A non-empty array of Credential Queries that specify the requested Credentials.
	 */
	private List<CredentialQuery> credentials;

	/**
	 * A non-empty array of Credential Set Queries that specifies additional constraints on which of the requested
	 * Credentials to return.
	 */
	private List<CredentialSetQuery> credentialSets;

}
