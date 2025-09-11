
package io.github.wistefan.dcql.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * A Credential Query is an object representing a request for a presentation of one or more matching Credentials.
 */
@Data
public class CredentialQuery {

	/**
	 * A string identifying the Credential in the response and, if provided, the constraints in credential_sets. The
	 * value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the
	 * Authorization Request, the same id MUST NOT be present more than once.
	 */
	private String id;

	/**
	 *  A string that specifies the format of the requested Credential.
	 */
	private CredentialFormat format;

	/**
	 * A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the
	 * default value is false. If empty, no specific constraints are placed on the metadata or validity of the requested Credential.
	 */
	private Boolean multiple = false;

	/**
	 * A non-empty array of objects  that specifies claims in the requested Credential. Verifiers MUST NOT point to the
	 * same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	 */
	private List<ClaimsQuery> claims;

	/**
	 * An object defining additional properties requested by the Verifier that apply to the metadata and validity data
	 * of the Credential. The properties of this object are defined per Credential Format. If empty, no specific
	 * constraints are placed on the metadata or validity of the requested Credential.
	 */
	private Map<String, Object> meta;

	/**
	 *  A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof. The default value
	 *  is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required. If set to false, the
	 *  Verifier accepts a Credential without Cryptographic Holder Binding proof.
	 */
	@JsonProperty("require_cryptographic_holder_binding")
	private Boolean requireCryptographicHolderBinding;

	/**
	 * A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of
	 * claims for the Credential are requested.
	 */
	@JsonProperty("claim_sets")
	private List<List<String>> claimSets;

	/**
	 * A non-empty array of objects  that specifies expected authorities or trust frameworks that certify Issuers, that
	 * the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions
	 * present in the corresponding trusted_authorities array if present.
	 */
	@JsonProperty("trusted_authorities")
	private List<TrustedAuthorityQuery> trustedAuthorities;
}
