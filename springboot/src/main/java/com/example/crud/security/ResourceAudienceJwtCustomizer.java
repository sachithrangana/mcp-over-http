package com.example.crud.security;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Binds tokens issued to the remote MCP client to that server as their audience.
 *
 * The MCP authorization spec requires a resource server to accept only tokens
 * minted for it, which normally comes from RFC 8707 resource indicators. Spring
 * Authorization Server does not implement those — it ignores the `resource`
 * parameter the client sends — so without this the token would carry no audience
 * and the MCP server would have nothing to check. Stamping `aud` here is what
 * lets remote_server.py refuse a token that was issued for something else.
 *
 * Only the remote client gets this. The local stdio plugin talks to the product
 * API directly, which does not check audience.
 */
@Component
public class ResourceAudienceJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final String remoteClientId;
    private final String resourceUrl;

    public ResourceAudienceJwtCustomizer(
            @Value("${crud.mcp.remote-client-id:crud-mcp-remote}") String remoteClientId,
            @Value("${crud.mcp.resource-url:http://localhost:3000}") String resourceUrl) {
        this.remoteClientId = remoteClientId;
        this.resourceUrl = resourceUrl;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }
        if (remoteClientId.equals(context.getRegisteredClient().getClientId())) {
            context.getClaims().audience(List.of(resourceUrl));
        }
    }
}
