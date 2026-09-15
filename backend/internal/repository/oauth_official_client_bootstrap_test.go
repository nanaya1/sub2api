package repository

import (
	"context"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/ent/oauthclient"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

const testOfficialOAuthClientID = "test-official-oauth-client"

func testOAuthServerConfig(enabled bool) *config.Config {
	return &config.Config{
		OAuthServer: config.OAuthServerConfig{
			Enabled:         enabled,
			ClientID:        testOfficialOAuthClientID,
			RedirectURI:     "meacowork://oauth/callback",
			RequirePKCES256: true,
		},
	}
}

func TestEnsureOAuthServerOfficialClientDisabledDoesNothing(t *testing.T) {
	client := newSecuritySecretTestClient(t)

	err := ensureOAuthServerOfficialClient(context.Background(), client, testOAuthServerConfig(false))
	require.NoError(t, err)

	count, err := client.OAuthClient.Query().Count(context.Background())
	require.NoError(t, err)
	require.Zero(t, count)
}

func TestEnsureOAuthServerOfficialClientCreatesTrustedRegistration(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	cfg := testOAuthServerConfig(true)

	err := ensureOAuthServerOfficialClient(context.Background(), client, cfg)
	require.NoError(t, err)

	stored, err := client.OAuthClient.Query().Where(oauthclient.ClientIDEQ(testOfficialOAuthClientID)).Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, "MeacoWork", stored.Name)
	require.Equal(t, "public", stored.ClientType)
	require.Equal(t, []string{cfg.OAuthServer.RedirectURI}, stored.RedirectUris)
	require.Equal(t, []string{"authorization_code", "refresh_token"}, stored.AllowedGrantTypes)
	require.Equal(t, service.OAuthServerScopes, stored.AllowedScopes)
	require.True(t, stored.RequirePkce)
	require.Equal(t, "active", stored.Status)
}

func TestEnsureOAuthServerOfficialClientUpdatesPolicyAndPreservesDisabledStatus(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	ctx := context.Background()
	_, err := client.OAuthClient.Create().
		SetClientID(testOfficialOAuthClientID).
		SetName("Legacy name").
		SetClientType("public").
		SetRedirectUris([]string{"https://legacy.example/callback"}).
		SetAllowedGrantTypes([]string{"authorization_code"}).
		SetAllowedScopes([]string{"profile"}).
		SetRequirePkce(false).
		SetStatus("disabled").
		Save(ctx)
	require.NoError(t, err)

	cfg := testOAuthServerConfig(true)
	require.NoError(t, ensureOAuthServerOfficialClient(ctx, client, cfg))
	require.NoError(t, ensureOAuthServerOfficialClient(ctx, client, cfg))

	stored, err := client.OAuthClient.Query().Where(oauthclient.ClientIDEQ(testOfficialOAuthClientID)).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, "MeacoWork", stored.Name)
	require.Equal(t, []string{cfg.OAuthServer.RedirectURI}, stored.RedirectUris)
	require.Equal(t, []string{"authorization_code", "refresh_token"}, stored.AllowedGrantTypes)
	require.Equal(t, service.OAuthServerScopes, stored.AllowedScopes)
	require.True(t, stored.RequirePkce)
	require.Equal(t, "disabled", stored.Status)

	count, err := client.OAuthClient.Query().Where(oauthclient.ClientIDEQ(testOfficialOAuthClientID)).Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestEnsureOAuthServerOfficialClientDoesNotModifyOtherClients(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	ctx := context.Background()
	other, err := client.OAuthClient.Create().
		SetClientID("other-client").
		SetName("Other client").
		SetClientType("public").
		SetRedirectUris([]string{"https://other.example/callback"}).
		SetAllowedGrantTypes([]string{"authorization_code"}).
		SetAllowedScopes([]string{"profile"}).
		SetRequirePkce(true).
		SetStatus("disabled").
		Save(ctx)
	require.NoError(t, err)

	require.NoError(t, ensureOAuthServerOfficialClient(ctx, client, testOAuthServerConfig(true)))

	stored, err := client.OAuthClient.Get(ctx, other.ID)
	require.NoError(t, err)
	require.Equal(t, "Other client", stored.Name)
	require.Equal(t, []string{"https://other.example/callback"}, stored.RedirectUris)
	require.Equal(t, []string{"authorization_code"}, stored.AllowedGrantTypes)
	require.Equal(t, []string{"profile"}, stored.AllowedScopes)
	require.True(t, stored.RequirePkce)
	require.Equal(t, "disabled", stored.Status)
}

func TestEnsureOAuthServerOfficialClientConcurrentCreation(t *testing.T) {
	client := newSecuritySecretTestClient(t)
	cfg := testOAuthServerConfig(true)
	const goroutines = 8

	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			errs[index] = ensureOAuthServerOfficialClient(context.Background(), client, cfg)
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	count, err := client.OAuthClient.Query().Where(oauthclient.ClientIDEQ(testOfficialOAuthClientID)).Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestEnsureOAuthServerOfficialClientRejectsNilInputs(t *testing.T) {
	err := ensureOAuthServerOfficialClient(context.Background(), nil, testOAuthServerConfig(true))
	require.ErrorContains(t, err, "nil ent client")

	client := newSecuritySecretTestClient(t)
	err = ensureOAuthServerOfficialClient(context.Background(), client, nil)
	require.ErrorContains(t, err, "nil config")
}
