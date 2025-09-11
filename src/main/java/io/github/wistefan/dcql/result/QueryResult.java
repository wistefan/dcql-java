
package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

// Using @JsonInclude(JsonInclude.Include.NON_NULL) to omit null fields from JSON output, matching TS behavior

@JsonInclude(JsonInclude.Include.NON_NULL)
public record QueryResult(
    boolean canBeSatisfied,
    @JsonProperty("credential_matches") Map<String, CredentialMatch> credentialMatches,
    @JsonProperty("credential_sets") List<CredentialSetResult> credentialSets
) {}
