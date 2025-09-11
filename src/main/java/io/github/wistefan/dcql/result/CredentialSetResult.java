
package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialSetResult(
    String purpose,
    Boolean required,
    List<List<String>> options,
    @JsonProperty("matching_options") List<List<String>> matchingOptions
) {}
