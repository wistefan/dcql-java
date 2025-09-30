package io.github.wistefan.dcql.model.credential;

import lombok.Getter;

import java.util.Map;

@Getter
public class MDocCredential extends CredentialBase {

    private static final String DOC_TYPE_KEY = "docType";

    private MDocHeaders headers;
    private Map<String, Object> payload;

    public MDocCredential(String raw, MDocHeaders headers, Map<String, Object> payload) {
        super(raw);
        this.headers = headers;
        this.payload = payload;
    }

    public String getDocType() {
        if (payload.containsKey(DOC_TYPE_KEY) && payload.get(DOC_TYPE_KEY) instanceof String docType) {
            return docType;
        }
        throw new IllegalArgumentException("The credential does not contain a valid docType.");
    }
}
