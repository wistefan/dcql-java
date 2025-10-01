package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.*;
import io.github.wistefan.dcql.model.credential.JwtCredential;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.github.wistefan.dcql.DCQLEvaluator.*;

/**
 * Evaluator implementation for JWT Credentials
 */
public class JwtCredentialEvaluator implements CredentialEvaluator<JwtCredential> {
    @Override
    public CredentialFormat supportedFormat() {
        return CredentialFormat.JWT_VC_JSON;
    }

    @Override
    public List<JwtCredential> translate(List<Credential> credentials) {
        return CredentialMapper.toJWTCredentials(credentials);

    }

    @Override
    public List<Credential> evaluate(CredentialQuery credentialQuery, List<JwtCredential> jwtCredentials) {
        if (containsMeta(credentialQuery)) {
            jwtCredentials = filterJwtByMetadata(credentialQuery.getMeta(), jwtCredentials);
        }
        if (containsTrustAuthorities(credentialQuery)) {
            for (TrustedAuthorityQuery taq : credentialQuery.getTrustedAuthorities()) {
                jwtCredentials = jwtCredentials.stream()
                        .filter(credential -> TrustedAuthoritiesEvaluator.evaluateQueryForJwtCredential(taq, credential))
                        .toList();
            }
        }
        if (containsClaims(credentialQuery) && !containsClaimSets(credentialQuery)) {
            for (ClaimsQuery cq : credentialQuery.getClaims()) {
                jwtCredentials = evaluateJwtCredentialsClaimQuery(cq, jwtCredentials);
            }
        } else if (containsClaims(credentialQuery)) {
            return evaluateForClaimSet(credentialQuery, jwtCredentials, JwtCredentialEvaluator::evaluateJwtCredentialsClaimQuery);
        }
        return CredentialMapper.toCredentials(CredentialFormat.JWT_VC_JSON, jwtCredentials);
    }

    private static List<JwtCredential> filterJwtByMetadata(Map<String, Object> metaData, List<JwtCredential> credentialsList) {
        W3CMetaData w3CMetaData = W3CMetaData.fromMeta(metaData);
        return credentialsList.stream()
                .filter(jwtCredential ->
                        w3CMetaData.getTypeValues()
                                .stream()
                                .anyMatch(metaTypes -> new HashSet<>(jwtCredential.getType()).containsAll(metaTypes)))
                .toList();
    }

    private static List<JwtCredential> evaluateJwtCredentialsClaimQuery(ClaimsQuery cq, List<JwtCredential> jwtCredentials) {
        return jwtCredentials.stream()
                .map(credential -> ClaimsEvaluator.evaluateClaimsForJwtCredential(cq, credential))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();
    }
}
