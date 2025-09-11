package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.*;
import io.github.wistefan.dcql.model.credential.*;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

@Slf4j
public class DCQLEvaluator {

	private static final String MDOC_NAMESPACE_KEY = "namespaces";

	public static List<Credential> evaluateDCQLQuery(DcqlQuery dcqlQuery, List<Credential> credentialsList) {
		List<Credential> selectedCredentials = new ArrayList<>();
		for (CredentialQuery cq : dcqlQuery.getCredentials()) {
			List<Credential> credentialsFullfilling = evaluateCredentialQuery(cq, credentialsList);
			if (credentialsFullfilling.isEmpty()) {
				log.debug("When one of the credentials requirements is not fulfilled, the query should fail.");
				return List.of();
			}
			selectedCredentials.addAll(credentialsFullfilling);
		}
		return selectedCredentials;
	}

	private static List<Credential> evaluateCredentialQuery(CredentialQuery credentialQuery, List<Credential> credentialsList) {

		if (!containsClaims(credentialQuery)
				&& containsClaims(credentialQuery)) {
			throw new IllegalArgumentException("Queries with claim_set require to have claims, too.");
		}

		List<Credential> filteredByFormat = filterByFormat(credentialQuery.getFormat(), credentialsList);
		return switch (credentialQuery.getFormat()) {
			case LDP_VC -> evaluateForLdpVC(credentialQuery, filteredByFormat);
			case MSO_MDOC -> evaluateForMDoc(credentialQuery, filteredByFormat);
			case DC_SD_JWT, VC_SD_JWT -> evaluateForSdJwt(credentialQuery, filteredByFormat);
			case JWT_VC_JSON -> evaluateForJwt(credentialQuery, filteredByFormat);
		};
	}

	private static List<Credential> evaluateForSdJwt(CredentialQuery credentialQuery, List<Credential> credentialsList) {
		List<SdJwtCredential> sdJwtCredentials = CredentialMapper.toSdJWTCredentials(credentialsList);
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
					.map(sdJwtCredential -> new SdJwtCredential(sdJwtCredential.getJwtCredential(), List.of()))
					.toList();
		}
		return CredentialMapper.toCredentials(credentialQuery.getFormat(), sdJwtCredentials);
	}

	private static List<Credential> evaluateForJwt(CredentialQuery credentialQuery, List<Credential> credentialsList) {
		List<JwtCredential> jwtCredentials = CredentialMapper.toJWTCredentials(credentialsList);
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
			return evaluateForClaimSet(credentialQuery, jwtCredentials, DCQLEvaluator::evaluateJwtCredentialsClaimQuery);
		}
		return CredentialMapper.toCredentials(CredentialFormat.JWT_VC_JSON, jwtCredentials);
	}

	private static List<Credential> evaluateForLdpVC(CredentialQuery credentialQuery, List<Credential> credentialsList) {
		List<LdpCredential> ldpCredentials = CredentialMapper.toLdpCredentials(credentialsList);
		if (containsMeta(credentialQuery)) {
			ldpCredentials = filterLdpByMetadata(credentialQuery.getMeta(), ldpCredentials);
		}

		if (containsClaims(credentialQuery) && !containsClaimSets(credentialQuery)) {
			for (ClaimsQuery cq : credentialQuery.getClaims()) {
				ldpCredentials = evaluateLdpCredentialsClaimQuery(cq, ldpCredentials);
			}
		} else if (containsClaims(credentialQuery)) {
			return evaluateForClaimSet(credentialQuery, ldpCredentials, DCQLEvaluator::evaluateLdpCredentialsClaimQuery);
		}

		return CredentialMapper.toCredentials(CredentialFormat.LDP_VC, ldpCredentials);
	}

	private static List<Credential> evaluateForMDoc(CredentialQuery credentialQuery, List<Credential> credentialsList) {
		List<MDocCredential> mDocCredentials = CredentialMapper.toMDocCredentials(credentialsList);
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
			return evaluateForClaimSet(credentialQuery, mDocCredentials, DCQLEvaluator::evaluateMDocCredentialsClaimQuery);
		}
		return CredentialMapper.toCredentials(CredentialFormat.MSO_MDOC, mDocCredentials);
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
					disclosedCredentials.add(new SdJwtCredential(credential.getJwtCredential(), new ArrayList<>(disclosures)));
				}
			}

			if (!disclosedCredentials.isEmpty()) {
				return CredentialMapper.toCredentials(credentialQuery.getFormat(), disclosedCredentials);
			}
		}
		return List.of();
	}

	// The method returns the first claim set that is fullfilled. It can contain multiple credentials, that would
	// fulfill the set individually, leaving the choice of what to share to the upstream.
	private static <T> List<Credential> evaluateForClaimSet(CredentialQuery credentialQuery, List<T> initialCredentials, BiFunction<ClaimsQuery, List<T>, List<T>> evaluationFunction) {
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
			disclosedCredentials.add(new SdJwtCredential(credential.getJwtCredential(), new ArrayList<>(selectedDisclosures)));
		}
		return disclosedCredentials;
	}

	private static List<SdJwtCredential> evaluateSdJwtCredentialsClaimQuery(ClaimsQuery cq, List<SdJwtCredential> sdJwtCredentials) {
		return sdJwtCredentials.stream()
				.map(credential -> ClaimsEvaluator.evaluateClaimsForSdJwtCredential(cq, credential))
				.filter(Optional::isPresent)
				.map(Optional::get)
				.toList();
	}

	private static List<LdpCredential> evaluateLdpCredentialsClaimQuery(ClaimsQuery cq, List<LdpCredential> ldpCredentials) {
		return ldpCredentials.stream()
				.map(credential -> ClaimsEvaluator.evaluateClaimsForLdpCredential(cq, credential))
				.filter(Optional::isPresent)
				.map(Optional::get)
				.toList();
	}

	private static List<JwtCredential> evaluateJwtCredentialsClaimQuery(ClaimsQuery cq, List<JwtCredential> jwtCredentials) {
		return jwtCredentials.stream()
				.map(credential -> ClaimsEvaluator.evaluateClaimsForJwtCredential(cq, credential))
				.filter(Optional::isPresent)
				.map(Optional::get)
				.toList();
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

	private static List<Credential> filterByFormat(CredentialFormat credentialFormat, List<Credential> credentialsList) {
		return credentialsList.stream()
				.filter(c -> c.getCredentialFormat() == credentialFormat)
				.toList();
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

	private static List<SdJwtCredential> filterSdJwtByMetadata(Map<String, Object> metaData, List<SdJwtCredential> credentialsList) {
		JwtMetaData jwtMetaData = JwtMetaData.fromMeta(metaData);
		return credentialsList.stream()
				.filter(sdJwtCredential -> jwtMetaData.getVctValues().contains(sdJwtCredential.getVct()))
				.toList();
	}

	private static List<JwtCredential> filterJwtByMetadata(Map<String, Object> metaData, List<JwtCredential> credentialsList) {
		JwtMetaData jwtMetaData = JwtMetaData.fromMeta(metaData);
		return credentialsList.stream()
				.filter(jwtCredential -> jwtMetaData.getVctValues().contains(jwtCredential.getVct()))
				.toList();
	}

	private static List<MDocCredential> filterMDocByMetadata(Map<String, Object> metaData, List<MDocCredential> credentialsList) {
		MDocMetaData mDocMetaData = MDocMetaData.fromMeta(metaData);
		return credentialsList.stream()
				.filter(mDocCredential -> mDocCredential.getDocType().equals(mDocMetaData.getDocType()))
				.toList();
	}

	private static boolean containsClaims(CredentialQuery credentialQuery) {
		return credentialQuery.getClaims() != null && !credentialQuery.getClaims().isEmpty();
	}

	private static boolean containsClaimSets(CredentialQuery credentialQuery) {
		return credentialQuery.getClaimSets() != null && !credentialQuery.getClaimSets().isEmpty();
	}

	private static boolean containsMeta(CredentialQuery credentialQuery) {
		return credentialQuery.getMeta() != null && !credentialQuery.getMeta().isEmpty();
	}

	private static boolean containsTrustAuthorities(CredentialQuery credentialQuery) {
		return credentialQuery.getTrustedAuthorities() != null && !credentialQuery.getTrustedAuthorities().isEmpty();
	}
}
