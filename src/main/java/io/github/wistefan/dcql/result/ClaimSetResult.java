package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClaimSetResult(
		boolean success,
		@JsonProperty("claim_set_index") Integer claimSetIndex,
		Map<String, Object> output,
		@JsonProperty("valid_claim_indexes") List<Integer> validClaimIndexes,
		@JsonProperty("failed_claim_indexes") List<Integer> failedClaimIndexes,
		Map<String, List<String>> issues
) {
}