package io.github.wistefan.dcql.model.credential;

import lombok.Getter;

import java.util.List;
import java.util.Map;

/**
 * Holder of LdpCredentials, providing access to its deserialized contents.
 */
@Getter
public class LdpCredential extends CredentialBase {

    private static final String TYPE_KEY = "type";

    private final Map<String, Object> theCredential;

    public LdpCredential(String raw, Map<String, Object> theCredential) {
        super(raw);
        this.theCredential = theCredential;
    }

    /**
     * Returns contents of the "type" field from the credential
     */
    public List<String> getType() {
        if (theCredential.containsKey(TYPE_KEY)) {
            if (theCredential.get(TYPE_KEY) instanceof String typeString) {
                return List.of(typeString);
            } else if (theCredential.get(TYPE_KEY) instanceof List typeList) {
                List<String> typeStrings = typeList.stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .toList();
                if (typeStrings.size() == typeList.size()) {
                    return typeStrings;
                }
            }
        }
        throw new IllegalArgumentException("The type field contains invalid entries.");
    }

}
