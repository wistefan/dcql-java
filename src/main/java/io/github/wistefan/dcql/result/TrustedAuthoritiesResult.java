
package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TrustedAuthoritiesResult(
    boolean success,
    @JsonProperty("valid_trusted_authority") TrustedAuthorityEvaluationResult validTrustedAuthority,
    @JsonProperty("failed_trusted_authorities") List<TrustedAuthorityEvaluationResult> failedTrustedAuthorities
) {}

