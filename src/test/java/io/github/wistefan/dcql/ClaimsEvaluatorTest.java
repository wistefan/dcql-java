package io.github.wistefan.dcql;

import io.github.wistefan.dcql.model.ClaimsQuery;
import io.github.wistefan.dcql.model.credential.Disclosure;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import io.github.wistefan.dcql.query.DcqlTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClaimsEvaluatorTest {

    @ParameterizedTest
    @MethodSource("jwtArgs")
    public void testEvaluateForJwtCredential(ClaimsQuery claimsQuery, Map<String, Object> credential, boolean expectedResult) {
        JwtCredential jwtCredential = new JwtCredential( null, null, credential, null);
        assertEquals(expectedResult, ClaimsEvaluator.evaluateClaimsForJwtCredential(claimsQuery, jwtCredential).isPresent());
    }

    @ParameterizedTest
    @MethodSource("sdJwtArgs")
    public void testEvaluateForJwtCredential(ClaimsQuery claimsQuery, Map<String, Object> payload, List<Disclosure> disclosures, Optional<List<Disclosure>> expectedDisclosures) {

        SdJwtCredential sdJwtCredential = new SdJwtCredential( null, new JwtCredential( null, null, payload, null), disclosures);
        Optional<SdJwtCredential> optionalSdJwtCredential = ClaimsEvaluator.evaluateClaimsForSdJwtCredential(claimsQuery, sdJwtCredential);

        assertEquals(expectedDisclosures.isPresent(), optionalSdJwtCredential.isPresent());
        expectedDisclosures.ifPresent(disclosureList -> assertEquals(disclosureList, optionalSdJwtCredential.get().getDisclosures()));
    }

    public static Stream<Arguments> sdJwtArgs() {
        return Stream.of(

                Arguments.of(
                        new ClaimsQuery("id", List.of("test", "a"), null),
                        Map.of("test", Map.of("_sd",
                                List.of(DcqlTest.getDisclosure("hash-a", "a", "b").getSdHash(),
                                        DcqlTest.getDisclosure("hash-b", "c", "d").getSdHash(), "decoy"))),
                        List.of(DcqlTest.getDisclosure("hash-a", "a", "b"), DcqlTest.getDisclosure("hash-b", "c", "d")),
                        Optional.of(List.of(DcqlTest.getDisclosure("hash-a", "a", "b")))),
                Arguments.of(
                        new ClaimsQuery("id", List.of("test", "a"), null),
                        Map.of("test", Map.of("_sd", List.of(DcqlTest.getDisclosure("hash-a", "a", "b").getSdHash(),
                                DcqlTest.getDisclosure("hash-b", "c", "d").getSdHash()))),
                        List.of(DcqlTest.getDisclosure("hash-a", "a", "b"), DcqlTest.getDisclosure("hash-b", "c", "d")),
                        Optional.of(List.of(DcqlTest.getDisclosure("hash-a", "a", "b")))),
                Arguments.of(
                        new ClaimsQuery("id", List.of("test", "a"), List.of("b")),
                        Map.of("test", Map.of("_sd", List.of(DcqlTest.getDisclosure("hash-a", "a", "b").getSdHash(),
                                DcqlTest.getDisclosure("hash-b", "c", "d").getSdHash()))),
                        List.of(DcqlTest.getDisclosure("hash-a", "a", "b"), DcqlTest.getDisclosure("hash-b", "c", "d")),
                        Optional.of(List.of(DcqlTest.getDisclosure("hash-a", "a", "b")))),
                Arguments.of(
                        new ClaimsQuery("id", List.of("test", "a"), List.of("c")),
                        Map.of("test", Map.of("_sd", List.of(DcqlTest.getDisclosure("hash-a", "a", "b").getSdHash(),
                                DcqlTest.getDisclosure("hash-b", "c", "d").getSdHash()))),
                        List.of(DcqlTest.getDisclosure("hash-a", "a", "b"), DcqlTest.getDisclosure("hash-b", "c", "d")),
                        Optional.empty()),
                Arguments.of(
                        new ClaimsQuery("id", List.of("a"), List.of("b")),
                        Map.of("_sd", List.of(DcqlTest.getDisclosure("hash-a", "a", "b").getSdHash(),
                                DcqlTest.getDisclosure("hash-b", "c", "d").getSdHash())),
                        List.of(DcqlTest.getDisclosure("hash-a", "a", "b"), DcqlTest.getDisclosure("hash-b", "c", "d")),
                        Optional.of(List.of(DcqlTest.getDisclosure("hash-a", "a", "b")))),
                Arguments.of(
                        new ClaimsQuery("id", List.of("a"), null),
                        Map.of("_sd", List.of(DcqlTest.getDisclosure("hash-a", "a", "b").getSdHash(),
                                DcqlTest.getDisclosure("hash-b", "c", "d").getSdHash())),
                        List.of(DcqlTest.getDisclosure("hash-a", "a", "b"), DcqlTest.getDisclosure("hash-b", "c", "d")),
                        Optional.of(List.of(DcqlTest.getDisclosure("hash-a", "a", "b")))),
                Arguments.of(
                        new ClaimsQuery("id", List.of("test", "e"), List.of("f")),
                        Map.of("_sd", List.of(DcqlTest.getDisclosure("hash-a", "a", "b").getSdHash(), DcqlTest.getDisclosure("hash-b", "c", "d").getSdHash()),
                                "test", Map.of("_sd", List.of(DcqlTest.getDisclosure("hash-c", "e", "f").getSdHash()))),
                        List.of(DcqlTest.getDisclosure("hash-a", "a", "b"), DcqlTest.getDisclosure("hash-b", "c", "d"), DcqlTest.getDisclosure("hash-c", "e", "f")),
                        Optional.of(List.of(DcqlTest.getDisclosure("hash-c", "e", "f"))))
        );
    }

    public static Stream<Arguments> jwtArgs() {
        List<Object> nullList = new ArrayList<>();
        nullList.add("test");
        nullList.add(null);
        nullList.add("a");
        return Stream.of(
                Arguments.of(new ClaimsQuery("id", nullList, null), Map.of("test", List.of(Map.of("a", "b"), Map.of("a", "d"))), true),
                Arguments.of(new ClaimsQuery("id", nullList, List.of("c")), Map.of("test", List.of(Map.of("a", "b"), Map.of("a", "d"))), false),
                Arguments.of(new ClaimsQuery("id", List.of("test", "a"), null), Map.of("test", Map.of("a", "b", "c", "d")), true),
                Arguments.of(new ClaimsQuery("id", List.of("test", "d"), null), Map.of("test", Map.of("a", "b", "c", "d")), false),
                Arguments.of(new ClaimsQuery("id", List.of("test", "a"), List.of("b")), Map.of("test", Map.of("a", "b", "c", "d")), true)
        );
    }
}