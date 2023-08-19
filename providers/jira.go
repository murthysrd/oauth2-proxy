package providers

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type JIRAProvider struct {
	*ProviderData
}

var _ Provider = (*JIRAProvider)(nil)

// NewJIRAProvider creates a JIRAProvider using the passed ProviderData
func NewJIRAProvider(p *ProviderData) *JIRAProvider {
	p.setProviderDefaults(providerDefaults{
		name:  "JIRA Data Center 3LO",
		scope: "WRITE",
	})

	p.getAuthorizationHeaderFunc = makeOIDCHeader

	return &JIRAProvider{ProviderData: p}
}

// EnrichSession uses the JIRA userinfo endpoint to populate the session's
// email and groups.
func (p *JIRAProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	for _, group := range json.Get("groups").Get("items").MustArray() {
		groupMap, ok := group.(map[string]interface{})
		if ok {
			for key, val := range groupMap {
				if key == "name" {
					s.Groups = append(s.Groups, val.(string))
				}
			}
		}
	}

	email, err := json.Get("emailAddress").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = email

	preferredUsername, err := json.Get("name").String()
	if err == nil {
		s.PreferredUsername = preferredUsername
	}

	user, err := json.Get("displayName").String()
	if err == nil {
		s.User = user
	}

	if s.User == "" && s.PreferredUsername != "" {
		s.User = s.PreferredUsername
	}

	return nil
}

// ValidateSession validates the AccessToken
func (p *JIRAProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
