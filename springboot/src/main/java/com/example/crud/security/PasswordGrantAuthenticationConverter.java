package com.example.crud.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Turns a POST /oauth2/token request carrying grant_type=password into a
 * {@link PasswordGrantAuthenticationToken}. Returns null for every other grant
 * so the built-in converters handle those.
 */
public final class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    private static final Set<String> KNOWN_PARAMETERS = Set.of(
            OAuth2ParameterNames.GRANT_TYPE,
            OAuth2ParameterNames.USERNAME,
            OAuth2ParameterNames.PASSWORD,
            OAuth2ParameterNames.SCOPE);

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!PasswordGrantAuthenticationToken.GRANT_TYPE.getValue().equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = parameters(request);

        String username = requireSingleValue(parameters, OAuth2ParameterNames.USERNAME);
        String password = requireSingleValue(parameters, OAuth2ParameterNames.PASSWORD);

        Set<String> scopes = new LinkedHashSet<>();
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope)) {
            if (parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
                throw invalidRequest(OAuth2ParameterNames.SCOPE);
            }
            scopes.addAll(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, values) -> {
            if (!KNOWN_PARAMETERS.contains(key)) {
                additionalParameters.put(key, values.get(0));
            }
        });

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        return new PasswordGrantAuthenticationToken(username, password, scopes, clientPrincipal, additionalParameters);
    }

    private static MultiValueMap<String, String> parameters(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        request.getParameterMap().forEach((key, values) -> parameters.addAll(key, Arrays.asList(values)));
        return parameters;
    }

    private static String requireSingleValue(MultiValueMap<String, String> parameters, String name) {
        List<String> values = parameters.get(name);
        if (values == null || values.size() != 1 || !StringUtils.hasText(values.get(0))) {
            throw invalidRequest(name);
        }
        return values.get(0);
    }

    private static OAuth2AuthenticationException invalidRequest(String parameterName) {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                "Missing or duplicate parameter: " + parameterName,
                "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
        return new OAuth2AuthenticationException(error);
    }
}
