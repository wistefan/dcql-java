package io.github.wistefan.dcql.model;

import lombok.Getter;

import java.util.Arrays;

public enum CredentialFormat {

	MSO_MDOC("mso_mdoc"),
	VC_SD_JWT("vc+sd-jwt"),
	DC_SD_JWT("dc+sd-jwt"),
	LDP_VC("ldp_vc"),
	JWT_VC_JSON("jwt_vc_json");

	@Getter
	private final String value;

	CredentialFormat(String value) {
		this.value = value;
	}

	public static CredentialFormat fromValue(String value) {
		return Arrays.stream(values())
				.filter(eV -> eV.getValue().equals(value))
				.findAny()
				.orElseThrow(() -> new IllegalArgumentException(String.format("Unknown value %s.", value)));
	}

	public String getValue() {
		return value;
	}

}
