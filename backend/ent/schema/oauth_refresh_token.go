package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"
	"github.com/google/uuid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthRefreshToken supports rotation and reuse detection. Each token belongs to a
// `family_id`; rotation links a new token to its `parent_token_id` and marks the
// old one via `replaced_by_token_id`. The absolute validity is `expires_at`
// while `idle_expires_at` enforces the idle TTL. Family-level revocation (and the
// required family lock) is implemented in a later service batch; the data model
// here already supports the relationships.
type OAuthRefreshToken struct {
	ent.Schema
}

func (OAuthRefreshToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_refresh_tokens"},
	}
}

func (OAuthRefreshToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (OAuthRefreshToken) Fields() []ent.Field {
	return []ent.Field{
		// HMAC hash of the refresh token. Raw token is never persisted.
		field.String("token_hash").
			MaxLen(255).
			NotEmpty().
			Unique(),
		// HMAC key version used to compute token_hash, enabling key rotation.
		field.Int("hash_key_version").
			Default(1),
		field.UUID("family_id", uuid.UUID{}),
		// Self-references for rotation lineage.
		field.Int64("parent_token_id").
			Optional().
			Nillable().
			Comment("Prior token in the rotation chain; null for the family root."),
		field.Int64("replaced_by_token_id").
			Optional().
			Nillable().
			Comment("Token that superseded this one during rotation."),
		field.JSON("scopes", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		field.Time("issued_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("expires_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}).
			Comment("Absolute validity deadline."),
		field.Time("idle_expires_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}).
			Comment("Idle validity deadline; null means no idle limit."),
		field.Time("last_used_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("revoked_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Int64("user_id"),
		field.Int64("client_id").
			Comment("Internal FK to oauth_clients.id."),
	}
}

func (OAuthRefreshToken) Edges() []ent.Edge {
	return []ent.Edge{
		// Inverse edges for the self-referencing rotation lineage.
		edge.To("child_tokens", OAuthRefreshToken.Type),
		edge.To("replaced_tokens", OAuthRefreshToken.Type),
		edge.From("user", User.Type).
			Ref("oauth_refresh_tokens").
			Field("user_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("client", OAuthClient.Type).
			Ref("oauth_refresh_tokens").
			Field("client_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("parent_token", OAuthRefreshToken.Type).
			Ref("child_tokens").
			Field("parent_token_id").
			Unique().
			Annotations(entsql.Annotation{OnDelete: entsql.SetNull}),
		edge.From("replaced_by_token", OAuthRefreshToken.Type).
			Ref("replaced_tokens").
			Field("replaced_by_token_id").
			Unique().
			Annotations(entsql.Annotation{OnDelete: entsql.SetNull}),
	}
}

func (OAuthRefreshToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token_hash").Unique(),
		index.Fields("user_id", "client_id"),
		index.Fields("family_id"),
		index.Fields("expires_at"),
	}
}
