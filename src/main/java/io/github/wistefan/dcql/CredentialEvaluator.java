package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.CredentialQuery;
import io.github.wistefan.dcql.model.credential.CredentialBase;

import java.util.List;

/**
 * Evaluator interface to execute queries on a certain type of credentials
 */
public interface CredentialEvaluator<T extends CredentialBase> {

    /**
     * Returns the {@link CredentialFormat} suppored by that evaluator.
     */
    CredentialFormat supportedFormat();

    /**
     * Translates the list of {@link Credential}s into the concrete types supported by that evaluator. Will fail if
     * the list contains other types.
     */
    List<T> translate(List<Credential> credentials);

    /**
     * Evaluate the query on the list of credentials.
     */
    List<Credential> evaluate(CredentialQuery credentialQuery, List<T> credentialsList);
}
