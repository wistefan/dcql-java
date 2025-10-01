package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.Credential;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Result of a DCQL evaluation
 *
 * @param success     - did the query succeed
 * @param credentials - the credentials returned by the query. If credential_sets is present, they are keyed by their
 *                    purpose or if omitted a random id.
 */
public record QueryResult(boolean success, Map<Object, List<Credential>> credentials) {
}
