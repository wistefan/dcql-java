
package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClaimsResult(
    boolean success,
    @JsonProperty("valid_claim_sets") List<ClaimSetResult> validClaimSets,
    @JsonProperty("failed_claim_sets") List<ClaimSetResult> failedClaimSets,
    @JsonProperty("valid_claims") List<ClaimEvaluationResult> validClaims,
    @JsonProperty("failed_claims") List<ClaimEvaluationResult> failedClaims
) {}



