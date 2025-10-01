package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.*;
import io.github.wistefan.dcql.model.credential.Disclosure;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;

import java.util.*;
import java.util.stream.Collectors;

import static io.github.wistefan.dcql.DCQLEvaluator.*;

/**
 * Evaluator implementation for SD-JWT Credentials
 */
public abstract class SdJwtCredentialEvaluator implements CredentialEvaluator<SdJwtCredential> {

    @Override
    public List<SdJwtCredential> translate(List<Credential> credentials) {
        return CredentialMapper.toSdJWTCredentials(credentials);
    }

    @Override
    public List<Credential> evaluate(CredentialQuery credentialQuery, List<SdJwtCredential> sdJwtCredentials) {
        if (containsMeta(credentialQuery)) {
            sdJwtCredentials = filterSdJwtByMetadata(credentialQuery.getMeta(), sdJwtCredentials);
        }
        if (containsTrustAuthorities(credentialQuery)) {
            for (TrustedAuthorityQuery taq : credentialQuery.getTrustedAuthorities()) {
                sdJwtCredentials = sdJwtCredentials.stream()
                        .filter(credential -> TrustedAuthoritiesEvaluator.evaluateQueryForSDJwtCredential(taq, credential))
                        .toList();
            }
        }
        if (containsClaims(credentialQuery) && !containsClaimSets(credentialQuery)) {
            sdJwtCredentials = evaluateSdJwtCredentialsQuery(credentialQuery, sdJwtCredentials);
        } else if (containsClaims(credentialQuery)) {
            return evaluateSdJwtForClaimSet(credentialQuery, sdJwtCredentials);
        } else {
            sdJwtCredentials = sdJwtCredentials.stream()
                    // keep the original credential untouched
                    .map(sdJwtCredential -> new SdJwtCredential(sdJwtCredential.getRaw(), sdJwtCredential.getJwtCredential(), List.of()))
                    .toList();
        }
        return CredentialMapper.toCredentials(credentialQuery.getFormat(), sdJwtCredentials);
    }

    private static List<SdJwtCredential> filterSdJwtByMetadata(Map<String, Object> metaData, List<SdJwtCredential> credentialsList) {
        JwtMetaData jwtMetaData = JwtMetaData.fromMeta(metaData);
        return credentialsList.stream()
                .filter(sdJwtCredential -> jwtMetaData.getVctValues().contains(sdJwtCredential.getVct()))
                .toList();
    }

    private static List<SdJwtCredential> evaluateSdJwtCredentialsQuery(CredentialQuery credentialQuery, List<SdJwtCredential> sdJwtCredentials) {
        List<SdJwtCredential> disclosedCredentials = new ArrayList<>();
        for (SdJwtCredential credential : sdJwtCredentials) {
            Set<Disclosure> selectedDisclosures = credentialQuery.getClaims()
                    .stream()
                    .map(cq -> ClaimsEvaluator.evaluateClaimsForSdJwtCredential(cq, credential))
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .map(SdJwtCredential::getDisclosures)
                    .flatMap(List::stream)
                    .collect(Collectors.toSet());
            disclosedCredentials.add(new SdJwtCredential(credential.getRaw(), credential.getJwtCredential(), new ArrayList<>(selectedDisclosures)));
        }
        return disclosedCredentials;
    }


    private static List<Credential> evaluateSdJwtForClaimSet(CredentialQuery credentialQuery, List<SdJwtCredential> sdJwtCredentials) {
        Map<String, ClaimsQuery> claimsQueryMap = new HashMap<>();
        credentialQuery.getClaims()
                .forEach(cq -> claimsQueryMap.put(cq.getId(), cq));

        for (List<String> claimSet : credentialQuery.getClaimSets()) {
            List<SdJwtCredential> disclosedCredentials = new ArrayList<>();
            for (SdJwtCredential credential : sdJwtCredentials) {
                Set<Disclosure> disclosures = new HashSet<>();
                for (String claimId : claimSet) {
                    ClaimsQuery claimsQuery = claimsQueryMap.get(claimId);
                    disclosures.addAll(new HashSet<>(
                            ClaimsEvaluator.evaluateClaimsForSdJwtCredential(claimsQuery, credential)
                                    .map(SdJwtCredential::getDisclosures)
                                    .orElse(new ArrayList<>())));
                }
                if (!disclosures.isEmpty()) {
                    disclosedCredentials.add(new SdJwtCredential(credential.getRaw(), credential.getJwtCredential(), new ArrayList<>(disclosures)));
                }
            }

            if (!disclosedCredentials.isEmpty()) {
                return CredentialMapper.toCredentials(credentialQuery.getFormat(), disclosedCredentials);
            }
        }
        return List.of();
    }

}
