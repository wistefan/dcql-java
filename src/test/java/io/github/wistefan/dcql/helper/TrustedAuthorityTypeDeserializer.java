package io.github.wistefan.dcql.helper;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import io.github.wistefan.dcql.model.TrustedAuthorityType;

import java.io.IOException;

public class TrustedAuthorityTypeDeserializer extends StdDeserializer<TrustedAuthorityType> {

	public TrustedAuthorityTypeDeserializer() {
		super(TrustedAuthorityType.class);
	}

	@Override
	public TrustedAuthorityType deserialize(JsonParser jsonParser, DeserializationContext context)
			throws IOException {
		String value = jsonParser.getText();
		return TrustedAuthorityType.fromValue(value);
	}
}