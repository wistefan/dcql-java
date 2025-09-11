package io.github.wistefan.dcql.model.credential;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdpCredential extends HashMap<String, Object> {

	private static final String TYPE_KEY = "type";

	public LdpCredential(Map<? extends String, ?> m) {
		super(m);
	}

	public List<String> getType() {
		if (this.containsKey(TYPE_KEY)) {
			if (this.get(TYPE_KEY) instanceof String typeString) {
				return List.of(typeString);
			} else if (this.get(TYPE_KEY) instanceof List typeList) {
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

}
