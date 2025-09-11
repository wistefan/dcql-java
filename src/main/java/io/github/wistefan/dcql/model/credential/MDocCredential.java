package io.github.wistefan.dcql.model.credential;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class MDocCredential {

	private static final String DOC_TYPE_KEY = "docType";

	private MDocHeaders headers;
	private Map<String, Object> payload;

	public String getDocType() {
		if (payload.containsKey(DOC_TYPE_KEY) && payload.get(DOC_TYPE_KEY) instanceof String docType) {
			return docType;
		}
		throw new IllegalArgumentException("The credential does not contain a valid docType.");
	}
}
