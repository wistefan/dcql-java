package io.github.wistefan.dcql.model.credential;

import io.github.wistefan.dcql.EvaluationException;
import lombok.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Disclosure object to provide values for an SD-JWT.
 */
@Data
@EqualsAndHashCode
public class Disclosure {
    private String salt;
    private String claim;
    private Object value;
    // the plain, encoded disclosure as it was provided in the original credential
    private final String encodedDisclosure;
    // the sd_hash of the disclosure, correlating with an _sd entry of the credential
    private final String sdHash;

    public Disclosure(String salt, String claim, Object value, String encodedDisclosure, String sdAlgorithm) {
        this.salt = salt;
        this.claim = claim;
        this.value = value;
        this.encodedDisclosure = encodedDisclosure;
        this.sdHash = generateSdHash(sdAlgorithm);
    }

    /**
     * Generate the hash of the disclosure, based on the algorithm(configured in the credential)
     */
    private String generateSdHash(String sdAlgorithm) {
        byte[] disclosureBytes = encodedDisclosure.getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = getMessageDigest(sdAlgorithm);

        byte[] hash = digest.digest(disclosureBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private MessageDigest getMessageDigest(String sdAlgorithm) {
        if (sdAlgorithm.equalsIgnoreCase("SHA-256")) {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new EvaluationException(String.format("SD-Algorithm %s is not supported.", sdAlgorithm), e);
            }
        }
        throw new EvaluationException(String.format("SD-Algorithm %s is not supported.", sdAlgorithm));
    }
}
