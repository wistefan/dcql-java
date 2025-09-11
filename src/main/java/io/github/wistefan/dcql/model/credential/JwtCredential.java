package io.github.wistefan.dcql.model.credential;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtCredential {

	private static final String VCT_KEY = "vct";
	private static final String TYPE_KEY = "type";
	private static final String X5C_KEY = "x5c";

	private Map<String, Object> headers;
	private Map<String, Object> payload;
	private String signature;

	public List<X509Certificate> getX5Chain() {
		if (headers.containsKey(X5C_KEY) && headers.get(X5C_KEY) instanceof List x5Chain) {
			List<X509Certificate> x509Certificates = x5Chain.stream()
					.filter(X509Certificate.class::isInstance)
					.map(X509Certificate.class::cast)
					.toList();
			if (x5Chain.size() != x509Certificates.size()) {
				throw new IllegalArgumentException("The x5c header contains invalid values.");
			}
			return x509Certificates;
		}
		// a x5c-header is not mandatory, thus an empty list is completely valid.
		return List.of();
	}

	public List<String> getType() {
		if (payload.containsKey(TYPE_KEY)) {
			if (payload.get(TYPE_KEY) instanceof String typeString) {
				return List.of(typeString);
			} else if (payload.get(TYPE_KEY) instanceof List typeList) {
				List<String> typeStrings = typeList.stream()
						.filter(String.class::isInstance)
						.map(String.class::cast)
						.toList();
				if (typeStrings.size() == typeList.size()) {
					return typeStrings;
				}
			}
		}
		throw new IllegalArgumentException("The type field contains invalid entries.");
	}

	public String getVct() {
		if (payload.containsKey(VCT_KEY) && payload.get(VCT_KEY) instanceof String vctValue) {
			return vctValue;
		}
		throw new IllegalArgumentException("Invalid credential. Does not contain a valid vct.");
	}

}
