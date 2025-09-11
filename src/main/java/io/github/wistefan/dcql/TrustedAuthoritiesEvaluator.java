package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.TrustedAuthorityQuery;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.MDocCredential;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Slf4j
public class TrustedAuthoritiesEvaluator {

	private static final String AKI_EXTENSION = "2.5.29.35";

	public static boolean evaluateQueryForMDocCredential(TrustedAuthorityQuery query, MDocCredential credential) {
		return switch (query.getType()) {
			case AKI -> isInChain(credential.getHeaders().getX5Chain(), query.getValues());
			case ETSI_TL -> isInEtsiTl(credential.getHeaders().getX5Chain(), query.getValues());
			case OPENID_FEDERATION -> isInOpenIdFederation(query.getValues());
		};
	}

	public static boolean evaluateQueryForSDJwtCredential(TrustedAuthorityQuery query, SdJwtCredential credential) {
		return evaluateQueryForJwtCredential(query, credential.getJwtCredential());
	}

	public static boolean evaluateQueryForJwtCredential(TrustedAuthorityQuery query, JwtCredential credential) {
		return switch (query.getType()) {
			case AKI -> isInChain(credential.getX5Chain(), query.getValues());
			case ETSI_TL -> isInEtsiTl(credential.getX5Chain(), query.getValues());
			case OPENID_FEDERATION -> isInOpenIdFederation(query.getValues());
		};
	}


	// ---- OpenID Federation ----
	private static boolean isInOpenIdFederation(List<String> federationValues) {
		throw new UnsupportedOperationException("Querying for OpenId Federation Trust Authorities is not yet supported.");
	}

	// ---- ETSI TL ----
	private static boolean isInEtsiTl(List<X509Certificate> x5chain, List<String> etsiTls) {
		throw new UnsupportedOperationException("Querying for etsi-tl is not supported at the moment.");
	}

	// ---- AKI ----

	private static boolean isInChain(List<X509Certificate> x5chain, List<String> akiValues) {
		return x5chain.stream()
				.map(TrustedAuthoritiesEvaluator::getAuthorityKeyIdentifier)
				.filter(Optional::isPresent)
				.map(Optional::get)
				.map(byteArray -> Base64.getUrlEncoder().encodeToString(byteArray))
				.anyMatch(akiValues::contains);
	}

	private static List<byte[]> decodeAki(List<String> akiValues) {
		return akiValues.stream()
				.map(v -> Base64.getUrlDecoder().decode(v))
				.toList();
	}

	public static Optional<byte[]> getAuthorityKeyIdentifier(X509Certificate certificate) {

		byte[] extValue = certificate.getExtensionValue(AKI_EXTENSION);
		if (extValue == null) {

			return Optional.empty();
		}
		ASN1OctetString akiOctet = ASN1OctetString.getInstance(extValue);
		ASN1Primitive akiObj = null;
		try {
			akiObj = ASN1Primitive.fromByteArray(akiOctet.getOctets());
		} catch (IOException e) {
			log.debug("Certificate does not contain a valid aki.", e);
			return Optional.empty();
		}
		AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(akiObj);
		return Optional.ofNullable(aki.getKeyIdentifier());
	}
}
