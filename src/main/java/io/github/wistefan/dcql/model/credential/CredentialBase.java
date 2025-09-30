package io.github.wistefan.dcql.model.credential;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public abstract class CredentialBase {

    protected final String raw;
}
