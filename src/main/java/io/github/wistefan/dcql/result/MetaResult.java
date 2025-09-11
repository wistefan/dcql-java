
package io.github.wistefan.dcql.result;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record MetaResult(
    boolean success,
    Map<String, Object> output,
    Map<String, List<String>> issues
) {}
