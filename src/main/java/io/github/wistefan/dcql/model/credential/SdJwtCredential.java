package io.github.wistefan.dcql.model.credential;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class SdJwtCredential {

	private JwtCredential jwtCredential;
	private List<Disclosure> disclosures;

	public String getVct() {
		return jwtCredential.getVct();
	}

	public List<String> getType() {
		return jwtCredential.getType();
	}
}
