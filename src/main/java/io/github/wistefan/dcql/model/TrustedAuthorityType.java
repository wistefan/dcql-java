package io.github.wistefan.dcql.model;

import lombok.Getter;

import java.util.Arrays;

/**
 * Type of trusted authorities to be used in queries{@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1}
 */
public enum TrustedAuthorityType {

	AKI("aki"),
	ETSI_TL("etsi_tl"),
	OPENID_FEDERATION("openid_federation");

	@Getter
	private final String value;

	TrustedAuthorityType(String value) {
		this.value = value;
	}

	public static TrustedAuthorityType fromValue(String value) {
		return Arrays.stream(values())
				.filter(eV -> eV.getValue().equals(value))
				.findAny()
				.orElseThrow(() -> new IllegalArgumentException(String.format("Unknown value %s.", value)));
	}

	public String getValue() {
		return value;
	}
}
