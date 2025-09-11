package io.github.wistefan.dcql.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class W3CMetaData {

	private static final String TYPE_VALUES_KEY = "type_values";

	private List<List<String>> typeValues;

	public static W3CMetaData fromMeta(Map<String, Object> metaData) {
		if (metaData.containsKey(TYPE_VALUES_KEY) && metaData.get(TYPE_VALUES_KEY) instanceof List typeValues) {

			List<List<String>> typeValuesStrings = typeValues.stream()
					.filter(List.class::isInstance)
					.map(l -> mapToStringList((List) l))
					.toList();
			if (typeValuesStrings.size() != typeValues.size()) {
				throw new IllegalArgumentException(String.format("The type_values %s contain invalid values.", typeValues));
			}
			return new W3CMetaData(typeValues);
		}
		throw new IllegalArgumentException(String.format("Given metaData %s is not w3c-metadata.", metaData));
	}

	private static List<String> mapToStringList(List listToMap) {
		List<String> stringList = listToMap.stream()
				.filter(String.class::isInstance)
				.map(String.class::cast)
				.toList();
		if (stringList.size() != listToMap.size()) {
			throw new IllegalArgumentException("Not all list entries are strings");
		}
		return stringList;
	}
}
