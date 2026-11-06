package handler

import (
	"context"
	"html"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (h *CoworkPortalHandler) keys(ctx context.Context, r *coworkPortalRequest) (any, error) {
	p := r.Parameters
	identity := r.CoworkPortalIdentity
	store := h.handlers.Provisioning.service
	keys := h.handlers.APIKey.apiKeyService
	if identity.TenantKey == "" {
		return nil, service.ErrPortalInvalid
	}
	if r.Operation == "key.page" {
		if p.Status != "" && p.Status != "active" && p.Status != "inactive" && p.Status != "expired" && p.Status != "quota_exhausted" {
			return nil, service.ErrPortalInvalid
		}
		ids, total, err := store.PortalKeyIDs(ctx, identity, p.Page, p.PageSize, p.Keyword, p.Status)
		if err != nil {
			return nil, err
		}
		result := []map[string]any{}
		for _, id := range ids {
			key, err := keys.GetByID(ctx, id)
			if err != nil {
				return nil, service.ErrPortalUnavailable
			}
			if key.UserID != identity.UserID {
				return nil, service.ErrPortalNotFound
			}
			result = append(result, coworkPortalKey(key, false))
		}
		return service.CoworkPortalPage(result, total, p.Page, p.PageSize), nil
	}
	if r.Operation == "key.add" || r.Operation == "key.edit" {
		if strings.TrimSpace(p.Name) == "" || utf8.RuneCountInString(p.Name) > 50 || p.Quota == nil || !finitePortalLimit(p.Quota) || !finitePortalLimit(p.RateLimit5h) || !finitePortalLimit(p.RateLimit1d) || !finitePortalLimit(p.RateLimit7d) || (p.ExpiresAt != nil && p.ClearExpiration) {
			return nil, service.ErrPortalInvalid
		}
		if p.ExpiresInDays != nil && (*p.ExpiresInDays < 1 || *p.ExpiresInDays > 3650) {
			return nil, service.ErrPortalInvalid
		}
		for _, rules := range []*[]string{p.IPWhitelist, p.IPBlacklist} {
			if rules != nil && (len(*rules) > 50 || len(ip.ValidateIPPatterns(*rules)) > 0) {
				return nil, service.ErrPortalInvalid
			}
		}
	}
	if r.Operation == "key.add" {
		group, err := store.PortalCurrentGroup(ctx, identity)
		if err != nil {
			return nil, err
		}
		return h.once(ctx, r, func() (int64, any, error) {
			request := service.CreateAPIKeyRequest{Name: p.Name, GroupID: &group, Quota: *p.Quota, ExpiresInDays: p.ExpiresInDays}
			if p.IPWhitelist != nil {
				request.IPWhitelist = *p.IPWhitelist
			}
			if p.IPBlacklist != nil {
				request.IPBlacklist = *p.IPBlacklist
			}
			if p.RateLimit5h != nil {
				request.RateLimit5h = *p.RateLimit5h
			}
			if p.RateLimit1d != nil {
				request.RateLimit1d = *p.RateLimit1d
			}
			if p.RateLimit7d != nil {
				request.RateLimit7d = *p.RateLimit7d
			}
			key, err := keys.Create(ctx, identity.UserID, request)
			if err != nil {
				return 0, nil, err
			}
			return key.ID, coworkPortalKey(key, true), nil
		})
	}
	if err := store.PortalOwnsKey(ctx, identity, p.ID); err != nil {
		return nil, err
	}
	switch r.Operation {
	case "key.remove":
		if err := keys.Delete(ctx, p.ID, identity.UserID); err != nil {
			return nil, portalMutationError(err)
		}
		return map[string]any{}, nil
	case "key.edit", "key.editStatus":
		var request service.UpdateAPIKeyRequest
		if r.Operation == "key.editStatus" {
			if p.Status != "active" && p.Status != "inactive" {
				return nil, service.ErrPortalInvalid
			}
			request.Status = &p.Status
		} else {
			request = service.UpdateAPIKeyRequest{Name: &p.Name, Quota: p.Quota, IPWhitelist: p.IPWhitelist, IPBlacklist: p.IPBlacklist, ExpiresAt: p.ExpiresAt, ClearExpiration: p.ClearExpiration, RateLimit5h: p.RateLimit5h, RateLimit1d: p.RateLimit1d, RateLimit7d: p.RateLimit7d}
		}
		// 不允许主系统重置消费计数、修改Key所有者或自动迁移分组
		key, err := keys.Update(ctx, p.ID, identity.UserID, request)
		if err != nil {
			return nil, portalMutationError(err)
		}
		return coworkPortalKey(key, false), nil
	default:
		key, err := keys.GetByID(ctx, p.ID)
		if err != nil {
			return nil, service.ErrPortalNotFound
		}
		if key.UserID != identity.UserID {
			return nil, service.ErrPortalNotFound
		}
		return coworkPortalKey(key, r.Operation == "key.reveal"), nil
	}
}

func coworkPortalKey(key *service.APIKey, reveal bool) map[string]any {
	masked := "********"
	if len(key.Key) > 12 {
		masked = key.Key[:7] + "…" + key.Key[len(key.Key)-4:]
	}
	var secret any
	if reveal {
		secret = key.Key
	}
	allow := key.IPWhitelist
	if allow == nil {
		allow = []string{}
	}
	deny := key.IPBlacklist
	if deny == nil {
		deny = []string{}
	}
	return map[string]any{"id": key.ID, "name": html.UnescapeString(key.Name), "maskedKey": masked, "key": secret, "status": key.Status, "quota": key.Quota, "quotaUsed": key.QuotaUsed, "rateLimit5h": key.RateLimit5h, "rateLimit1d": key.RateLimit1d, "rateLimit7d": key.RateLimit7d, "ipWhitelist": allow, "ipBlacklist": deny, "expiresAt": key.ExpiresAt, "createTime": key.CreatedAt}
}
