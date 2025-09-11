package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.ClaimsQuery;
import io.github.wistefan.dcql.model.credential.*;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class ClaimsEvaluator {

	private static final String SD_KEY = "_sd";

	public static Optional<MDocCredential> evaluateClaimsForMDocCredential(ClaimsQuery claimsQuery, MDocCredential credential) {
		List<SelectedClaim> selectedClaims = new ArrayList<>();
		try {
			selectedClaims = selectClaimsByPath(credential.getPayload(), claimsQuery.getPath());
		} catch (IllegalArgumentException iae) {
			log.debug("Did not find the requested claims.", iae);
			return Optional.empty();
		}

		if (claimsQuery.getValues() == null || claimsQuery.getValues().isEmpty()) {
			return Optional.of(credential);
		}

		// checks if a value exists in the selected claims, that is not in the list of allowedValues.
		if (selectedClaims.stream().allMatch(sC -> claimsQuery.getValues().contains(sC.value()))) {
			return Optional.of(credential);
		}
		return Optional.empty();
	}

	public static Optional<SdJwtCredential> evaluateClaimsForSdJwtCredential(ClaimsQuery claimsQuery, SdJwtCredential credential) {
		List<SelectedClaim> selectedClaims = new ArrayList<>();
		try {
			selectedClaims = selectClaimsByPathDisclosures(credential.getJwtCredential().getPayload(), claimsQuery.getPath(), credential.getDisclosures());
		} catch (IllegalArgumentException iae) {
			log.debug("Did not find the requested claims.", iae);
			return Optional.empty();
		}

		if (claimsQuery.getValues() == null || claimsQuery.getValues().isEmpty()) {
			return Optional.of(cleanUpDisclosures(selectedClaims, credential));
		}

		// checks if a value exists in the selected claims, that is not in the list of allowedValues.
		if (selectedClaims.stream().allMatch(sC -> claimsQuery.getValues().contains(sC.value()))) {
			return Optional.of(cleanUpDisclosures(selectedClaims, credential));
		}
		return Optional.empty();
	}

	private static SdJwtCredential cleanUpDisclosures(List<SelectedClaim> selectedClaims, SdJwtCredential credential) {
		Set<String> hashsToInclude = selectedClaims.stream().map(SelectedClaim::hash).collect(Collectors.toSet());
		List<Disclosure> cleanedDisclosures = credential.getDisclosures()
				.stream()
				.filter(disclosure -> hashsToInclude.contains(disclosure.getHash()))
				.toList();
		return new SdJwtCredential(credential.getJwtCredential(), cleanedDisclosures);
	}

	public static Optional<JwtCredential> evaluateClaimsForJwtCredential(ClaimsQuery claimsQuery, JwtCredential credential) {
		List<SelectedClaim> selectedClaims = new ArrayList<>();
		try {
			selectedClaims = selectClaimsByPath(credential.getPayload(), claimsQuery.getPath());
		} catch (IllegalArgumentException iae) {
			log.debug("Did not find the requested claims.", iae);
			return Optional.empty();
		}
		if (claimsQuery.getValues() == null || claimsQuery.getValues().isEmpty()) {
			return Optional.of(credential);
		}

		// checks if a value exists in the selected claims, that is not in the list of allowedValues.
		if (selectedClaims.stream().allMatch(sC -> claimsQuery.getValues().contains(sC.value()))) {
			return Optional.of(credential);
		}
		return Optional.empty();
	}

	public static Optional<LdpCredential> evaluateClaimsForLdpCredential(ClaimsQuery claimsQuery, LdpCredential credential) {
		List<SelectedClaim> selectedClaims = new ArrayList<>();
		try {
			selectedClaims = selectClaimsByPath(credential, claimsQuery.getPath());
		} catch (IllegalArgumentException iae) {
			log.debug("Did not find the requested claims.", iae);
			return Optional.empty();
		}
		if (claimsQuery.getValues() == null || claimsQuery.getValues().isEmpty()) {
			return Optional.of(credential);
		}

		// checks if a value exists in the selected claims, that is not in the list of allowedValues.
		if (selectedClaims.stream().allMatch(sC -> claimsQuery.getValues().contains(sC.value()))) {
			return Optional.of(credential);
		}
		return Optional.empty();
	}


	public static List<SelectedClaim> selectClaimsByPath(Map<String, Object> credential, List<Object> claimPath) {
		return processPath(credential, claimPath, null);
	}

	public static List<SelectedClaim> selectClaimsByPathDisclosures(Map<String, Object> credential, List<Object> claimPath,
																	List<Disclosure> disclosures) {
		return processPath(credential, claimPath, disclosures);
	}

	private static List<SelectedClaim> processPath(
			Map<String, Object> credential,
			List<Object> claimPath,
			List<Disclosure> disclosures
	) {
		if (credential == null || claimPath == null || claimPath.isEmpty()) {
			throw new IllegalArgumentException("Credential and claimPath must not be null or empty");
		}

		// Start with root
		List<SelectedClaim> current = new ArrayList<>();
		current.add(new SelectedClaim(credential, null));

		for (Object component : claimPath) {
			List<SelectedClaim> nextSelection = new ArrayList<>();

			for (SelectedClaim candidateWrapper : current) {
				Object candidate = candidateWrapper.value;

				// If map contains _sd, reveal it and MERGE revealed entries with the original map
				if (disclosures != null && candidate instanceof Map<?, ?> mapCandidate && mapCandidate.containsKey("_sd")) {
					Object sdObj = mapCandidate.get("_sd");
					Map<String, SelectedClaim> revealed = getStringSelectedClaimMap(disclosures, sdObj);

					// Merge: start with revealed, then copy original entries (except "_sd"),
					// so explicit values in the original map overwrite revealed ones if keys collide.
					Map<String, Object> merged = new LinkedHashMap<>();
					merged.putAll(revealed);
					for (Map.Entry<?, ?> e : mapCandidate.entrySet()) {
						String k = String.valueOf(e.getKey());
						if (SD_KEY.equals(k)) continue;
						merged.put(k, e.getValue());
					}
					candidate = merged;
				}

				// Process path component
				if (component instanceof String key) {
					if (!(candidate instanceof Map<?, ?> map)) {
						throw new IllegalArgumentException("Expected object for key lookup but found: " + candidate);
					}
					if (map.containsKey(key)) {
						Object val = map.get(key);
						if (val instanceof SelectedClaim sc) {
							nextSelection.add(sc);
						} else {
							nextSelection.add(new SelectedClaim(val, null));
						}
					}
				} else if (component == null) {
					if (!(candidate instanceof List<?> list)) {
						throw new IllegalArgumentException("Expected array for null selector but found: " + candidate);
					}
					for (Object elem : list) {
						if (elem instanceof SelectedClaim sc) {
							nextSelection.add(sc);
						} else {
							nextSelection.add(new SelectedClaim(elem, null));
						}
					}
				} else if (component instanceof Integer index && index >= 0) {
					if (!(candidate instanceof List<?> list)) {
						throw new IllegalArgumentException("Expected array for index selector but found: " + candidate);
					}
					if (index < list.size()) {
						Object val = list.get(index);
						if (val instanceof SelectedClaim sc) {
							nextSelection.add(sc);
						} else {
							nextSelection.add(new SelectedClaim(val, null));
						}
					}
				} else {
					throw new IllegalArgumentException("Invalid claim path component: " + component);
				}
			}

			if (nextSelection.isEmpty()) {
				throw new IllegalArgumentException("No elements selected at path component: " + component);
			}

			current = nextSelection;
		}

		return current;
	}


	private static Map<String, SelectedClaim> getStringSelectedClaimMap(List<Disclosure> disclosures, Object sdObj) {
		if (!(sdObj instanceof List<?> sdList)) {
			throw new IllegalArgumentException("_sd field must be a list");
		}

		Map<String, SelectedClaim> revealed = new LinkedHashMap<>();
		for (Object hashObj : sdList) {
			if (!(hashObj instanceof String hash)) continue;
			for (Disclosure disclosure : disclosures) {
				if (hash.equals(disclosure.getHash())) {
					revealed.put(disclosure.getClaim(), new SelectedClaim(disclosure.getValue(), disclosure.getHash()));
				}
			}
		}
		return revealed;
	}

	private record SelectedClaim(Object value, String hash) {
	}

}
