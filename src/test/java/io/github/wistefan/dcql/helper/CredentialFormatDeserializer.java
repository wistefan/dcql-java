package io.github.wistefan.dcql.helper;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import io.github.wistefan.dcql.model.CredentialFormat;

import java.io.IOException;

public class CredentialFormatDeserializer extends StdDeserializer<CredentialFormat> {

	public CredentialFormatDeserializer() {
		super(CredentialFormat.class);
	}

	@Override
	public CredentialFormat deserialize(JsonParser jsonParser, DeserializationContext context)
			throws IOException {
		String value = jsonParser.getText();
		return CredentialFormat.fromValue(value);
	}
}