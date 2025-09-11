package io.github.wistefan.dcql.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtMetaData {
	private static final String VCT_VALUES_KEY = "vct_values";

	private Set<String> vctValues;

	public static JwtMetaData fromMeta(Map<String, Object> metaData) {
		if (metaData.containsKey(VCT_VALUES_KEY) && metaData.get(VCT_VALUES_KEY) instanceof List vctValues) {
			List<String> vctStrings = vctValues.stream()
					.filter(String.class::isInstance)
					.map(String.class::cast)
					.toList();
			if (vctValues.size() != vctStrings.size()) {
				throw new IllegalArgumentException(String.format("The vct_values %s contain invalid values.", vctValues));
			}
			return new JwtMetaData(new HashSet<>(vctStrings));
		}
		throw new IllegalArgumentException(String.format("Given metaData %s is not sdJwt-metadata.", metaData));
	}
}