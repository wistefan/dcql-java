package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.credential.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Helper class to map raw {@link Credential}s into concrete Credential-Classes.
 */
public class CredentialMapper {

    /**
     * Convert the list of raw credentials into typed credentials.
     *
     * @param credentialFormat format of the credentials in the list
     * @param rawCredentials   raw credentials to be mapped
     * @return the list of typed credentials
     */
    public static List<Credential> toCredentials(CredentialFormat credentialFormat, List<?> rawCredentials) {
        return rawCredentials.stream()
                .filter(CredentialBase.class::isInstance)
                .map(CredentialBase.class::cast)
                .map(rC -> new Credential(credentialFormat, rC))
                .toList();
    }

    /**
     * Return the {@link LdpCredential}s from the given list. Fails if the list is multi-credential.
     */
    public static List<LdpCredential> toLdpCredentials(List<Credential> credentialsList) {
        List<LdpCredential> ldpCredentialsList = new ArrayList<>();
        for (Credential c : credentialsList) {
            if (c.getRawCredential() instanceof LdpCredential ldpCredential) {
                ldpCredentialsList.add(ldpCredential);
            } else {
                throw new IllegalArgumentException("The given credential does not contain an ldp_vc.");
            }
        }
        return ldpCredentialsList;
    }

    /**
     * Return the {@link MDocCredential}s from the given list. Fails if the list is multi-credential.
     */
    public static List<MDocCredential> toMDocCredentials(List<Credential> credentialsList) {
        List<MDocCredential> mDocCredentialsList = new ArrayList<>();
        for (Credential c : credentialsList) {
            if (c.getRawCredential() instanceof MDocCredential mDocCredential) {
                mDocCredentialsList.add(mDocCredential);
            } else {
                throw new IllegalArgumentException("The given credential does not contain an mso_mdoc.");
            }
        }
        return mDocCredentialsList;
    }

    /**
     * Return the {@link JwtCredential}s from the given list. Fails if the list is multi-credential.
     */
    public static List<JwtCredential> toJWTCredentials(List<Credential> credentialsList) {
        List<JwtCredential> jwtCredentialsList = new ArrayList<>();
        for (Credential c : credentialsList) {
            if (c.getRawCredential() instanceof JwtCredential jwtCredential) {
                jwtCredentialsList.add(jwtCredential);
            } else {
                throw new IllegalArgumentException("The given credential does not contain an jwt_vc_json.");
            }
        }
        return jwtCredentialsList;
    }

    /**
     * Return the {@link SdJwtCredential}s from the given list. Fails if the list is multi-credential.
     */
    public static List<SdJwtCredential> toSdJWTCredentials(List<Credential> credentialsList) {
        List<SdJwtCredential> sdJwtCredentialsList = new ArrayList<>();
        for (Credential c : credentialsList) {
            if (c.getRawCredential() instanceof SdJwtCredential sdJWTCredential) {
                sdJwtCredentialsList.add(sdJWTCredential);
            } else {
                throw new IllegalArgumentException("The given credential does not contain an vc+sd-jwt/dc+sd-jwt.");
            }
        }
        return sdJwtCredentialsList;
    }
}
