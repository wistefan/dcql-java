
package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialEvaluationResult(
    boolean success,
    @JsonProperty("input_credential_index") int inputCredentialIndex,
    MetaResult meta,
    ClaimsResult claims,
    @JsonProperty("trusted_authorities") TrustedAuthoritiesResult trustedAuthorities
) {}
