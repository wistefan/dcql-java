package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.*;
import io.github.wistefan.dcql.model.credential.MDocCredential;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.github.wistefan.dcql.DCQLEvaluator.*;

/**
 * Evaluator for MDoc Credentials
 */
public class MDocCredentialEvaluator implements CredentialEvaluator<MDocCredential> {

    // key to the namespaces in an MDoc credential
    private static final String MDOC_NAMESPACE_KEY = "namespaces";

    @Override
    public CredentialFormat supportedFormat() {
        return CredentialFormat.MSO_MDOC;
    }

    @Override
    public List<MDocCredential> translate(List<Credential> credentials) {
        return CredentialMapper.toMDocCredentials(credentials);
    }

    @Override
    public List<Credential> evaluate(CredentialQuery credentialQuery, List<MDocCredential> mDocCredentials) {
        if (containsMeta(credentialQuery)) {
            mDocCredentials = filterMDocByMetadata(credentialQuery.getMeta(), mDocCredentials);
        }
        if (containsTrustAuthorities(credentialQuery)) {
            for (TrustedAuthorityQuery taq : credentialQuery.getTrustedAuthorities()) {
                mDocCredentials = mDocCredentials.stream()
                        .filter(credential -> TrustedAuthoritiesEvaluator.evaluateQueryForMDocCredential(taq, credential))
                        .toList();
            }
        }
        translateMDocQueries(credentialQuery);
        if (containsClaims(credentialQuery) && !containsClaimSets(credentialQuery)) {
            for (ClaimsQuery cq : credentialQuery.getClaims()) {
                mDocCredentials = evaluateMDocCredentialsClaimQuery(cq, mDocCredentials);
            }
        } else if (containsClaims(credentialQuery)) {
            return evaluateForClaimSet(credentialQuery, mDocCredentials, MDocCredentialEvaluator::evaluateMDocCredentialsClaimQuery);
        }
        return CredentialMapper.toCredentials(CredentialFormat.MSO_MDOC, mDocCredentials);
    }

    private static List<MDocCredential> filterMDocByMetadata(Map<String, Object> metaData, List<MDocCredential> credentialsList) {
        MDocMetaData mDocMetaData = MDocMetaData.fromMeta(metaData);
        return credentialsList.stream()
                .filter(mDocCredential -> mDocCredential.getDocType().equals(mDocMetaData.getDocType()))
                .toList();
    }

    private static CredentialQuery translateMDocQueries(CredentialQuery credentialQuery) {
        if (credentialQuery.getClaims() == null) {
            return credentialQuery;
        }
        credentialQuery.getClaims()
                .forEach(cq -> {
                    if (isMDocClaimsQuery(cq) && cq.getNamespace() != null) {
                        cq.setPath(List.of(MDOC_NAMESPACE_KEY, cq.getNamespace(), cq.getClaimName()));
                    } else {
                        cq.getPath().addFirst(MDOC_NAMESPACE_KEY);
                    }
                });
        return credentialQuery;
    }

    private static List<MDocCredential> evaluateMDocCredentialsClaimQuery(ClaimsQuery cq, List<MDocCredential> mDocCredentials) {
        return mDocCredentials.stream()
                .map(credential -> ClaimsEvaluator.evaluateClaimsForMDocCredential(cq, credential))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();
    }

    private static boolean isMDocClaimsQuery(ClaimsQuery claimsQuery) {
        if ((claimsQuery.getNamespace() != null && claimsQuery.getClaimName() == null) || (claimsQuery.getNamespace() == null && claimsQuery.getClaimName() != null)) {
            throw new IllegalArgumentException("When a namespace or claim_name is set, the other parameter is mandatory.");
        }
        return claimsQuery.getIntent_to_retain() != null || claimsQuery.getNamespace() != null;
    }


}
