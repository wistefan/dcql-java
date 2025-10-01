package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.CredentialFormat;

public class VcSdJwtCredentialEvaluator extends SdJwtCredentialEvaluator {
    @Override
    public CredentialFormat supportedFormat() {
        return CredentialFormat.VC_SD_JWT;
    }
}
