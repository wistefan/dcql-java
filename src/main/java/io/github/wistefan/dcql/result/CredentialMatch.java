
package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialMatch(
    boolean success,
    @JsonProperty("credential_query_id") String credentialQueryId,
    @JsonProperty("valid_credentials") List<CredentialEvaluationResult> validCredentials,
    @JsonProperty("failed_credentials") List<CredentialEvaluationResult> failedCredentials
) {}
