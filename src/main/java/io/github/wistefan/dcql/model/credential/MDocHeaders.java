package io.github.wistefan.dcql.model.credential;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Holds MDoc-Specific headers and provides access to them
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MDocHeaders {

	private String alg;
	private List<X509Certificate> x5Chain;
}
