package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthManagedAPIKey is the stable binding between a (user, client) pair and the
// existing API Key that the client uses to call the inference gateway.
//
// Batch 1 deliberately stores ONLY the binding (user_id, client_id, api_key_id)
// and lifecycle timestamps. It does NOT store a second copy of the API key
// ciphertext/material; the existing `api_keys` table remains the single source of
// truth for gateway authentication. Encrypted, recoverable key material (if ever
// needed) belongs to a later batch and must not be introduced here.
type OAuthManagedAPIKey struct {
	ent.Schema
}

func (OAuthManagedAPIKey) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_managed_api_keys"},
	}
}

func (OAuthManagedAPIKey) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (OAuthManagedAPIKey) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("user_id"),
		field.Int64("client_id").
			Comment("Internal FK to oauth_clients.id."),
		field.Int64("api_key_id").
			Comment("Internal FK to api_keys.id."),
		field.Time("revoked_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
	}
}

func (OAuthManagedAPIKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("oauth_managed_api_keys").
			Field("user_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("client", OAuthClient.Type).
			Ref("oauth_managed_api_keys").
			Field("client_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("api_key", APIKey.Type).
			Ref("oauth_managed_api_keys").
			Field("api_key_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}

func (OAuthManagedAPIKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_id").Unique(),
		index.Fields("api_key_id").Unique(),
	}
}
