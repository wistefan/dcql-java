package io.github.wistefan.dcql.model.credential;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Base class for all credentials. Provides access to the raw credential, without any deserialization applied.
 */
@Getter
@RequiredArgsConstructor
public abstract class CredentialBase {

    protected final String raw;
}
