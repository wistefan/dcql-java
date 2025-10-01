package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.*;
import io.github.wistefan.dcql.model.credential.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

/**
 * Evaluator for DCQL Queries{@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l}
 */
@RequiredArgsConstructor
@Slf4j
public class DCQLEvaluator {

    // default key for non-credential-set results.
    private static final String DEFAULT_KEY = "credentials";

    private final List<CredentialEvaluator> credentialEvaluators;

    public QueryResult evaluateDCQLQuery(DcqlQuery dcqlQuery, List<Credential> credentialsList) {
        if (containsCredentialSets(dcqlQuery)) {
            // linked map to contain set order
            Map<Object, List<Credential>> resultMap = new LinkedHashMap<>();
            validateIds(dcqlQuery.getCredentials());
            Map<String, CredentialQuery> credentialQueryMap = new HashMap<>();
            dcqlQuery.getCredentials()
                    .forEach(cq -> credentialQueryMap.put(cq.getId(), cq));
            for (CredentialSetQuery credentialSetQuery : dcqlQuery.getCredentialSets()) {
                List<Credential> credentialsForSet = evaluateCredentialSetQuery(credentialQueryMap, credentialSetQuery, credentialsList);
                if (credentialsForSet.isEmpty() && credentialSetQuery.getRequired()) {
                    log.debug("The query cannot be fulfilled, since a required set is empty.");
                    return new QueryResult(false, Map.of());
                }
                resultMap.put(purposeOrRandom(credentialSetQuery), credentialsForSet);
            }
            return new QueryResult(true, resultMap);
        } else {
            List<Credential> selectedCredentials = new ArrayList<>();
            for (CredentialQuery cq : dcqlQuery.getCredentials()) {
                List<Credential> credentialsFullfilling = evaluateCredentialQuery(cq, credentialsList);
                if (credentialsFullfilling.isEmpty()) {
                    log.debug("When one of the credentials requirements is not fulfilled, the query should fail.");
                    return new QueryResult(false, Map.of());
                }
                if (!cq.getMultiple() && credentialsFullfilling.size() != 1) {
                    log.debug("Multiple credentials where returend for a query not allowing multiple.");
                    return new QueryResult(false, Map.of());
                }
                selectedCredentials.addAll(credentialsFullfilling);
            }
            // if no sets are requested, put the credentials at one
            return new QueryResult(true, Map.of(DEFAULT_KEY, selectedCredentials));
        }

    }

    private List<Credential> evaluateCredentialSetQuery(Map<String, CredentialQuery> credentialQueryMap,
                                                        CredentialSetQuery credentialSetQuery,
                                                        List<Credential> credentials) {
        for (List<String> option : credentialSetQuery.getOptions()) {
            // set to prevent duplicates
            Set<Credential> fullfillingCredentials = new HashSet<>();
            fullfillingCredentials.addAll(
                    option.stream()
                            .map(credentialQueryMap::get)
                            .map(cq -> evaluateCredentialQuery(cq, credentials))
                            .flatMap(List::stream)
                            .collect(Collectors.toSet()));
            // return the first option that fulfills the query
            if (!fullfillingCredentials.isEmpty()) {
                return new ArrayList<>(fullfillingCredentials);
            }
        }
        return List.of();
    }

    private List<Credential> evaluateCredentialQuery(CredentialQuery credentialQuery, List<Credential> credentialsList) {

        if (!containsClaims(credentialQuery)
                && containsClaimSets(credentialQuery)) {
            throw new IllegalArgumentException("Queries with claim_set require to have claims, too.");
        }

        List<Credential> filteredByFormat = filterByFormat(credentialQuery.getFormat(), credentialsList);
        CredentialEvaluator credentialEvaluator = this.credentialEvaluators
                .stream()
                .filter(evaluator -> evaluator.supportedFormat() == credentialQuery.getFormat())
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException(String.format("The format %s is not supported. Consider registering a matching evaluator.", credentialQuery.getFormat())));
        return credentialEvaluator.evaluate(credentialQuery, credentialEvaluator.translate(filteredByFormat));
    }

    // The method returns the first claim set that is fullfilled. It can contain multiple credentials, that would
    // fulfill the set individually, leaving the choice of what to share to the upstream.
    protected static <T> List<Credential> evaluateForClaimSet(CredentialQuery credentialQuery, List<T> initialCredentials, BiFunction<ClaimsQuery, List<T>, List<T>> evaluationFunction) {
        Map<String, ClaimsQuery> claimsQueryMap = new HashMap<>();
        credentialQuery.getClaims()
                .forEach(cq -> claimsQueryMap.put(cq.getId(), cq));

        for (List<String> claimSet : credentialQuery.getClaimSets()) {
            List<T> credentialsForClaimSet = new ArrayList<>(initialCredentials);
            for (String claimId : claimSet) {
                ClaimsQuery claimsQuery = claimsQueryMap.get(claimId);
                credentialsForClaimSet = evaluationFunction.apply(claimsQuery, credentialsForClaimSet);
            }
            if (!credentialsForClaimSet.isEmpty()) {
                return CredentialMapper.toCredentials(credentialQuery.getFormat(), credentialsForClaimSet);
            }
        }
        return List.of();
    }


    private static List<Credential> filterByFormat(CredentialFormat credentialFormat, List<Credential> credentialsList) {
        return credentialsList.stream()
                .filter(c -> c.getCredentialFormat() == credentialFormat)
                .toList();
    }


    public static boolean containsClaims(CredentialQuery credentialQuery) {
        return credentialQuery.getClaims() != null && !credentialQuery.getClaims().isEmpty();
    }

    public static boolean containsClaimSets(CredentialQuery credentialQuery) {
        return credentialQuery.getClaimSets() != null && !credentialQuery.getClaimSets().isEmpty();
    }

    public static boolean containsMeta(CredentialQuery credentialQuery) {
        return credentialQuery.getMeta() != null && !credentialQuery.getMeta().isEmpty();
    }

    public static boolean containsTrustAuthorities(CredentialQuery credentialQuery) {
        return credentialQuery.getTrustedAuthorities() != null && !credentialQuery.getTrustedAuthorities().isEmpty();
    }

    public static boolean containsCredentialSets(DcqlQuery dcqlQuery) {
        return dcqlQuery.getCredentialSets() != null && !dcqlQuery.getCredentialSets().isEmpty();
    }

    private static void validateIds(List<CredentialQuery> credentialQueries) {
        if (credentialQueries.stream().anyMatch(cq -> cq.getId() == null)) {
            throw new IllegalArgumentException("All credentialQueries need to contain an id.");
        }
    }

    private static Object purposeOrRandom(CredentialSetQuery credentialSetQuery) {
        return Optional.ofNullable(credentialSetQuery.getPurpose()).orElse(UUID.randomUUID().toString());
    }
}
