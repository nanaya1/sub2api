package repository

import (
	"encoding/json"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func oauthHashCandidatesJSON(candidates []service.OAuthSecretHash, legacyHash string) (string, error) {
	if len(candidates) == 0 && legacyHash != "" {
		candidates = []service.OAuthSecretHash{{Version: 1, Hash: legacyHash}}
	}
	payload := make([]struct {
		Version int    `json:"version"`
		Hash    string `json:"hash"`
	}, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Version > 0 && candidate.Hash != "" {
			payload = append(payload, struct {
				Version int    `json:"version"`
				Hash    string `json:"hash"`
			}{Version: candidate.Version, Hash: candidate.Hash})
		}
	}
	encoded, err := json.Marshal(payload)
	return string(encoded), err
}
