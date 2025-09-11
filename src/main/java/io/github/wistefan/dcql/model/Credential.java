package io.github.wistefan.dcql.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Credential {

	private CredentialFormat credentialFormat;
	private Object rawCredential;
}
