package handler

import (
	"context"
	"encoding/json"
	"html"
	"reflect"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// clientConfig 不保存或创建Key，不走操作防重写链路；权限及事实变化时整份快照失败。
func (h *CoworkPortalHandler) clientConfig(ctx context.Context, r *coworkPortalRequest) (any, error) {
	store := h.handlers.Provisioning.service
	ids, err := store.PortalClientKeyIDs(ctx, r.CoworkPortalIdentity)
	if err != nil {
		return nil, err
	}
	providers := []map[string]any{}
	snapshots := map[int64]map[string]any{}
	for _, id := range ids {
		key, err := h.handlers.APIKey.apiKeyService.GetByID(ctx, id)
		if err != nil || !clientKeyUsable(key, r.UserID) {
			return nil, service.ErrPortalUnavailable
		}
		models, err := h.clientModels(ctx, key.Group)
		if err != nil {
			return nil, err
		}
		snapshots[id] = clientKeySnapshot(key)
		providers = append(providers, map[string]any{"id": key.ID, "groupId": *key.GroupID,
			"name": html.UnescapeString(key.Name), "apiKey": key.Key, "platform": key.Group.Platform, "models": models})
	}
	if err := store.ResolvePortalIdentity(ctx, &r.CoworkPortalIdentity); err != nil {
		return nil, err
	}
	current, err := store.PortalClientKeyIDs(ctx, r.CoworkPortalIdentity)
	if err != nil || !reflect.DeepEqual(ids, current) {
		return nil, service.ErrPortalUnavailable
	}
	for _, id := range ids {
		key, err := h.handlers.APIKey.apiKeyService.GetByID(ctx, id)
		if err != nil || !clientKeyUsable(key, r.UserID) || !reflect.DeepEqual(snapshots[id], clientKeySnapshot(key)) {
			return nil, service.ErrPortalUnavailable
		}
	}
	// 回显完整输入范围，Java可以区分已确认的空结果与下游部分处理。
	return map[string]any{"keyIds": r.Parameters.APIKeyIDs, "providers": providers}, nil
}

// 正式分组授权由前后两次PortalClientKeyIDs在SQL中复核；GetByID不加载AllowedGroups。
func clientKeyUsable(key *service.APIKey, userID int64) bool {
	return key != nil && key.UserID == userID && key.IsActive() && !key.IsExpired() && !key.IsQuotaExhausted() &&
		key.GroupID != nil && key.Group != nil && key.Group.ID == *key.GroupID && key.Group.IsActive() &&
		key.User != nil && key.User.IsActive() && key.User.RestrictPublicGroups
}

func clientKeySnapshot(key *service.APIKey) map[string]any {
	result := coworkPortalKey(key, true)
	result["groupUpdatedAt"] = key.Group.UpdatedAt
	result["modelAllowlist"] = key.Group.ModelAllowlist
	result["manifest"] = key.Group.CodexModelsManifestConfig
	return result
}

func (h *CoworkPortalHandler) clientModels(ctx context.Context, group *service.Group) ([]string, error) {
	if group.Platform != service.PlatformOpenAI && group.Platform != service.PlatformAnthropic &&
		group.Platform != service.PlatformGemini && group.Platform != service.PlatformGrok {
		return nil, service.ErrPortalUnavailable
	}
	gateway := h.handlers.Gateway
	if gateway == nil || gateway.gatewayService == nil {
		return nil, service.ErrPortalUnavailable
	}
	var models []string
	if group.Platform == service.PlatformOpenAI && group.CodexModelsManifestConfig.Enabled {
		if gateway.openAIGatewayService == nil {
			return nil, service.ErrPortalUnavailable
		}
		manifest, _, err := gateway.openAIGatewayService.FetchPinnedOpenAIModelsList(ctx, group, gateway.maxAccountSwitches, "")
		if err != nil || manifest == nil {
			return nil, service.ErrPortalUnavailable
		}
		var list struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(manifest.Body, &list) != nil || list.Data == nil {
			return nil, service.ErrPortalUnavailable
		}
		for _, model := range list.Data {
			models = append(models, model.ID)
		}
	} else {
		// 候选目录取正式平台目录及分组精确条目，由实时账号模型准入规则筛选。
		candidates := append([]string{}, defaultModelIDsForPlatform(group.Platform)...)
		if group.ModelAllowlistEnabled() {
			candidates = append(candidates, group.ModelAllowlist.Models...)
		}
		var err error
		models, err = gateway.gatewayService.DiscoverCoworkModels(ctx, group.ID, group.Platform, candidates)
		if err != nil {
			return nil, err
		}
	}
	if group.ModelAllowlistEnabled() {
		models = group.ModelAllowlist.FilterForListing(models)
	}
	if len(models) > 4000 {
		return nil, service.ErrPortalUnavailable
	}
	result := []string{}
	seen := map[string]bool{}
	for _, model := range models {
		if strings.TrimSpace(model) == "" || strings.ContainsAny(model, "*?#\r\n") {
			return nil, service.ErrPortalUnavailable
		}
		if !seen[model] {
			result = append(result, model)
			seen[model] = true
		}
	}
	return result, nil
}
