package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.CredentialFormat;

public class DcSdJwtCredentialEvaluator extends SdJwtCredentialEvaluator {
    @Override
    public CredentialFormat supportedFormat() {
        return CredentialFormat.DC_SD_JWT;
    }

}
