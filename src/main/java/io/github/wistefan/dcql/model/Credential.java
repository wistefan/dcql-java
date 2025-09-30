package io.github.wistefan.dcql.model;

import io.github.wistefan.dcql.model.credential.CredentialBase;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Credential {

    private CredentialFormat credentialFormat;
    private CredentialBase rawCredential;
}
