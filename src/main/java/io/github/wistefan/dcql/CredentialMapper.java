package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.LdpCredential;
import io.github.wistefan.dcql.model.credential.MDocCredential;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;

import java.util.ArrayList;
import java.util.List;

public class CredentialMapper {

	public static List<Credential> toCredentials(CredentialFormat credentialFormat, List<?> rawCredentials) {
		return rawCredentials.stream()
				.map(rC -> new Credential(credentialFormat, rC))
				.toList();
	}

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
