package io.github.wistefan.dcql.model.credential;

import lombok.Getter;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * Holder of JwtCredentials, providing access to its deserialized contents.
 */
@Getter
public class JwtCredential extends CredentialBase {

    private static final String VC_PAYLOAD_KEY = "vc";
    private static final String VCT_KEY = "vct";
    private static final String TYPE_KEY = "type";
    private static final String X5C_KEY = "x5c";

    private final Map<String, Object> headers;
    private final Map<String, Object> payload;
    private final String signature;

    public JwtCredential(String raw, Map<String, Object> headers, Map<String, Object> payload, String signature) {
        super(raw);
        this.headers = headers;
        this.payload = payload;
        this.signature = signature;
    }

    /**
     * Returns the certificates from the "x5c" header from the credential, if the header exists
     */
    public List<X509Certificate> getX5Chain() {
        if (headers.containsKey(X5C_KEY) && headers.get(X5C_KEY) instanceof List x5Chain) {
            List<X509Certificate> x509Certificates = x5Chain.stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList();
            if (x5Chain.size() != x509Certificates.size()) {
                throw new IllegalArgumentException("The x5c header contains invalid values.");
            }
            return x509Certificates;
        }
        // a x5c-header is not mandatory, thus an empty list is completely valid.
        return List.of();
    }

    /**
     * Returns the concrete "vc" entry from the payload.
     */
    public Map<String, Object> getPayload() {
        if (payload.containsKey(VC_PAYLOAD_KEY)) {
            return (Map<String, Object>) payload.get(VC_PAYLOAD_KEY);
        }
        return payload;
    }

    /**
     * Returns contents of the "type" field from the credential
     */
    public List<String> getType() {
        if (getPayload().containsKey(TYPE_KEY)) {
            if (getPayload().get(TYPE_KEY) instanceof String typeString) {
                return List.of(typeString);
            } else if (getPayload().get(TYPE_KEY) instanceof List typeList) {
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

    /**
     * Returns contents of the "vct" field of the credential.
     */
    public String getVct() {
        if (getPayload().containsKey(VCT_KEY) && getPayload().get(VCT_KEY) instanceof String vctValue) {
            return vctValue;
        }
        throw new IllegalArgumentException("Invalid credential. Does not contain a valid vct.");
    }

}
