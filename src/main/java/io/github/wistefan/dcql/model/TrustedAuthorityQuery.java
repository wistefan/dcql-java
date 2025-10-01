
package io.github.wistefan.dcql.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * An object representing information that helps to identify an authority or the trust framework that certifies Issuers.
 * A Credential is identified as a match to a Trusted Authorities Query if it matches with one of the provided values in
 * one of the provided types.
 * {@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1}
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
public class TrustedAuthorityQuery {

	/**
	 * A string uniquely identifying the type of information about the issuer trust framework. Types defined by this
	 * specification are listed below.
	 */
	private TrustedAuthorityType type;

	/**
	 * A non-empty array of strings, where each string (value) contains information specific to the used Trusted
	 * Authorities Query type that allows the identification of an issuer, a trust framework, or a federation that an
	 * issuer belongs to.
	 */
	private List<String> values;
}