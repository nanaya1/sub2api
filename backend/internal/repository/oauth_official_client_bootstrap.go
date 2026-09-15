package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/oauthclient"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const officialOAuthClientName = "MeacoWork"

var officialOAuthClientGrantTypes = []string{"authorization_code", "refresh_token"}

// ensureOAuthServerOfficialClient synchronizes the trusted built-in public client
// after migrations. Existing status is intentionally preserved so an operator's
// explicit disabled state cannot be undone by a restart.
func ensureOAuthServerOfficialClient(ctx context.Context, client *ent.Client, cfg *config.Config) error {
	if client == nil {
		return fmt.Errorf("nil ent client")
	}
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if !cfg.OAuthServer.Enabled {
		return nil
	}

	clientID := strings.TrimSpace(cfg.OAuthServer.ClientID)
	redirectURI := strings.TrimSpace(cfg.OAuthServer.RedirectURI)
	if clientID == "" {
		return fmt.Errorf("oauth_server.client_id is required for official client bootstrap")
	}
	if redirectURI == "" {
		return fmt.Errorf("oauth_server.redirect_uri is required for official client bootstrap")
	}

	existing, err := client.OAuthClient.Query().Where(oauthclient.ClientIDEQ(clientID)).Only(ctx)
	if err == nil {
		return updateOfficialOAuthClient(ctx, existing, redirectURI)
	}
	if !ent.IsNotFound(err) {
		return fmt.Errorf("query official OAuth client %q: %w", clientID, err)
	}

	_, err = client.OAuthClient.Create().
		SetClientID(clientID).
		SetName(officialOAuthClientName).
		SetClientType("public").
		SetRedirectUris([]string{redirectURI}).
		SetAllowedGrantTypes(append([]string(nil), officialOAuthClientGrantTypes...)).
		SetAllowedScopes(append([]string(nil), service.OAuthServerScopes...)).
		SetRequirePkce(true).
		SetStatus("active").
		Save(ctx)
	if err == nil {
		return nil
	}
	if !ent.IsConstraintError(err) {
		return fmt.Errorf("create official OAuth client %q: %w", clientID, err)
	}

	// A concurrent instance may have inserted the same client between the query and create.
	// Reloading by client_id also prevents unrelated constraint failures from being treated as success.
	existing, reloadErr := client.OAuthClient.Query().Where(oauthclient.ClientIDEQ(clientID)).Only(ctx)
	if reloadErr != nil {
		return fmt.Errorf("create official OAuth client %q: %w (reload after constraint error: %v)", clientID, err, reloadErr)
	}
	return updateOfficialOAuthClient(ctx, existing, redirectURI)
}

func updateOfficialOAuthClient(ctx context.Context, existing *ent.OAuthClient, redirectURI string) error {
	if _, err := existing.Update().
		SetName(officialOAuthClientName).
		SetClientType("public").
		SetRedirectUris([]string{redirectURI}).
		SetAllowedGrantTypes(append([]string(nil), officialOAuthClientGrantTypes...)).
		SetAllowedScopes(append([]string(nil), service.OAuthServerScopes...)).
		SetRequirePkce(true).
		Save(ctx); err != nil {
		return fmt.Errorf("update official OAuth client %q: %w", existing.ClientID, err)
	}
	return nil
}
