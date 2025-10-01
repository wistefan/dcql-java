package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.*;
import io.github.wistefan.dcql.model.credential.LdpCredential;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.github.wistefan.dcql.DCQLEvaluator.*;

/**
 * Evaluator for LDP Credentials
 */
public class LdpCredentialEvaluator implements CredentialEvaluator<LdpCredential> {

    @Override
    public CredentialFormat supportedFormat() {
        return CredentialFormat.LDP_VC;
    }

    @Override
    public List<LdpCredential> translate(List<Credential> credentials) {
        return CredentialMapper.toLdpCredentials(credentials);
    }

    @Override
    public List<Credential> evaluate(CredentialQuery credentialQuery, List<LdpCredential> ldpCredentials) {

        if (containsMeta(credentialQuery)) {
            ldpCredentials = filterLdpByMetadata(credentialQuery.getMeta(), ldpCredentials);
        }

        if (containsClaims(credentialQuery) && !containsClaimSets(credentialQuery)) {
            for (ClaimsQuery cq : credentialQuery.getClaims()) {
                ldpCredentials = evaluateLdpCredentialsClaimQuery(cq, ldpCredentials);
            }
        } else if (containsClaims(credentialQuery)) {
            return evaluateForClaimSet(credentialQuery, ldpCredentials, LdpCredentialEvaluator::evaluateLdpCredentialsClaimQuery);
        }

        return CredentialMapper.toCredentials(CredentialFormat.LDP_VC, ldpCredentials);
    }


    private static List<LdpCredential> filterLdpByMetadata(Map<String, Object> metaData, List<LdpCredential> credentialsList) {
        W3CMetaData w3CMetaData = W3CMetaData.fromMeta(metaData);
        return credentialsList.stream()
                .filter(ldpCredential ->
                        w3CMetaData.getTypeValues()
                                .stream()
                                .anyMatch(metaTypes -> new HashSet<>(ldpCredential.getType()).containsAll(metaTypes)))
                .toList();
    }

    private static List<LdpCredential> evaluateLdpCredentialsClaimQuery(ClaimsQuery cq, List<LdpCredential> ldpCredentials) {
        return ldpCredentials.stream()
                .map(credential -> ClaimsEvaluator.evaluateClaimsForLdpCredential(cq, credential))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();
    }

}
