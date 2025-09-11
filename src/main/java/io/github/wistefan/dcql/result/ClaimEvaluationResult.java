package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClaimEvaluationResult(
		boolean success,
		@JsonProperty("claim_index") int claimIndex,
		@JsonProperty("claim_id") String claimId,
		Map<String, Object> output,
		Map<String, List<String>> issues
) {
}
