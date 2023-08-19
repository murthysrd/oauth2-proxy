package providers

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"golang.org/x/oauth2"
)

type JIRAProvider struct {
	*OIDCProvider
}

const (
	jiraProviderName = "JIRA Data Center 3LO"
	jiraDefaultScope = "WRITE"
)

// NewJIRAProvider creates a JIRAProvider using the passed ProviderData
func NewJIRAProvider(p *ProviderData) *JIRAProvider {

	p.setProviderDefaults(providerDefaults{
		name:  jiraProviderName,
		scope: jiraDefaultScope,
	})

	p.getAuthorizationHeaderFunc = makeOIDCHeader

	provider := &JIRAProvider{
		OIDCProvider: &OIDCProvider{
			ProviderData: p,
		},
	}

	return provider
}

var _ Provider = (*JIRAProvider)(nil)

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *JIRAProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	if codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	return p.createSession(ctx, token, false)
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

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *JIRAProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *JIRAProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	// curl -X POST https://atlassian.example.com/rest/oauth2/latest/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&refresh_token=REFRESH_TOKEN&grant_type=refresh_token&redirect_uri=REDIRECT_URI

	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var data struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&data)
	if err != nil {
		logger.Errorf("failed to redeem refresh_token %v", err)
		return err
	}

	logger.Printf("Token Redeemed. New Token valid for %v", data.ExpiresIn)
	s.AccessToken = data.AccessToken
	s.RefreshToken = data.RefreshToken

	s.CreatedAtNow()
	s.ExpiresIn(time.Duration(data.ExpiresIn) * time.Second)

	return nil
}

// createSession takes an oauth2.Token and creates a SessionState from it.
// It alters behavior if called from Redeem vs Refresh
func (p *JIRAProvider) createSession(ctx context.Context, token *oauth2.Token, refresh bool) (*sessions.SessionState, error) {

	ss, err := p.buildSessionFromClaims(token.AccessToken, "")
	if err != nil {
		return nil, err
	}

	ss.AccessToken = token.AccessToken
	ss.RefreshToken = token.RefreshToken
	ss.IDToken = token.AccessToken

	logger.Printf("Session Created. Token valid for %v", token.Expiry)
	ss.CreatedAtNow()
	ss.SetExpiresOn(token.Expiry)

	return ss, nil
}
