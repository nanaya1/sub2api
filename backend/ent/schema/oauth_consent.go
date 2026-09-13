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

// OAuthConsent records that a user has authorized a client for a set of scopes.
// The (user_id, client_id) pair is unique; re-consent updates the scopes and
// clears revoked_at rather than inserting a new row.
type OAuthConsent struct {
	ent.Schema
}

func (OAuthConsent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_consents"},
	}
}

func (OAuthConsent) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (OAuthConsent) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("user_id"),
		field.Int64("client_id").
			Comment("Internal FK to oauth_clients.id."),
		field.JSON("scopes", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		field.Time("revoked_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
	}
}

func (OAuthConsent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("oauth_consents").
			Field("user_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("client", OAuthClient.Type).
			Ref("oauth_consents").
			Field("client_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}

func (OAuthConsent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_id").Unique(),
	}
}
