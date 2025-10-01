package io.github.wistefan.dcql.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Holder of metadata-queries for the MDoc format
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class MDocMetaData {

	private static final String DOCTYPE_KEY = "doctype_value";

	private String docType;

	/**
	 * Extract the supported metadata(e.g. doctype_value) information for MDoc credentials.
	 */
	public static MDocMetaData fromMeta(Map<String, Object> metaData) {
		if (metaData.containsKey(DOCTYPE_KEY) && metaData.get(DOCTYPE_KEY) instanceof String docType) {
			return new MDocMetaData(docType);
		}
		throw new IllegalArgumentException(String.format("Given metaData %s is not mDoc-metadata.", metaData));
	}
}
