package io.github.wistefan.dcql.model.credential;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
@EqualsAndHashCode
public class Disclosure {
	private String hash;
	private String claim;
	private Object value;
}
