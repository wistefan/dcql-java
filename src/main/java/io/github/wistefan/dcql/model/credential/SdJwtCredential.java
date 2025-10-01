package io.github.wistefan.dcql.model.credential;

import lombok.Getter;

import java.util.List;
import java.util.StringJoiner;

/**
 * Holder of SdJwtCredential, providing access to its deserialized contents.
 */
@Getter
public class SdJwtCredential extends CredentialBase {

    private static final String SD_JWT_SEPARATOR = "~";

    /**
     * The "standard"-jwt contents of the credential
     */
    private JwtCredential jwtCredential;
    /**
     * The disclosures to provide access to the contents
     */
    private List<Disclosure> disclosures;

    public SdJwtCredential(String raw, JwtCredential jwtCredential, List<Disclosure> disclosures) {
        super(raw);
        this.jwtCredential = jwtCredential;
        this.disclosures = disclosures;
    }

    /**
     * For SD-JWT Credentials we cannot return the full raw-credential, since we might disclose claims that are not requested.
     * Instead, the "raw" needs to be rebuilt from the jwt-part and the selected disclosures.
     */
    @Override
    public String getRaw() {
        if (raw == null) {
            return null;
        }
        String[] splittedRaw = super.getRaw().split(SD_JWT_SEPARATOR);
        StringJoiner sdJoiner = new StringJoiner(SD_JWT_SEPARATOR);
        // first element is the plain jwt.
        sdJoiner.add(splittedRaw[0]);
        disclosures.stream()
                .map(Disclosure::getEncodedDisclosure)
                .forEach(sdJoiner::add);
        // the sd needs to end with an ~
        return sdJoiner + SD_JWT_SEPARATOR;
    }

    public String getVct() {
        return jwtCredential.getVct();
    }

    public List<String> getType() {
        return jwtCredential.getType();
    }

}
