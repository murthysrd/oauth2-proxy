package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const (
	JiraAccessToken  = "eyJIRA.eyJAccess.Token"
	JiraUserinfoPath = "/api/v3/user"
)

func testJIRAProvider(backend *httptest.Server) (*JIRAProvider, error) {
	p := NewJIRAProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})

	if backend != nil {
		bURL, err := url.Parse(backend.URL)
		if err != nil {
			return nil, err
		}
		hostname := bURL.Host

		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}

	return p, nil
}

var _ = Describe("JIRA Provider Tests", func() {
	Context("New Provider Init", func() {
		It("uses defaults", func() {
			providerData := NewJIRAProvider(&ProviderData{}).Data()
			Expect(providerData.ProviderName).To(Equal("JIRA Data Center 3LO"))
			Expect(providerData.LoginURL.String()).To(Equal(""))
			Expect(providerData.RedeemURL.String()).To(Equal(""))
			Expect(providerData.ProfileURL.String()).To(Equal(""))
			Expect(providerData.ValidateURL.String()).To(Equal(""))
			Expect(providerData.Scope).To(Equal("WRITE"))
		})

		It("overrides defaults", func() {
			p := NewJIRAProvider(
				&ProviderData{
					LoginURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/oauth/auth"},
					RedeemURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/oauth/token"},
					ProfileURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/api/v3/user"},
					ValidateURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/api/v3/user"},
					Scope: "WRITE"})
			providerData := p.Data()

			Expect(providerData.ProviderName).To(Equal("JIRA Data Center 3LO"))
			Expect(providerData.LoginURL.String()).To(Equal("https://example.com/oauth/auth"))
			Expect(providerData.RedeemURL.String()).To(Equal("https://example.com/oauth/token"))
			Expect(providerData.ProfileURL.String()).To(Equal("https://example.com/api/v3/user"))
			Expect(providerData.ValidateURL.String()).To(Equal("https://example.com/api/v3/user"))
			Expect(providerData.Scope).To(Equal("WRITE"))
		})
	})

	Context("EnrichSession", func() {
		type enrichSessionTableInput struct {
			backendHandler http.HandlerFunc
			expectedError  error
			expectedEmail  string
			expectedGroups []string
		}

		DescribeTable("should return expected results",
			func(in enrichSessionTableInput) {
				backend := httptest.NewServer(in.backendHandler)
				p, err := testJIRAProvider(backend)
				Expect(err).To(BeNil())

				p.ProfileURL, err = url.Parse(
					fmt.Sprintf("%s%s", backend.URL, JiraUserinfoPath),
				)
				Expect(err).To(BeNil())

				session := &sessions.SessionState{AccessToken: JiraAccessToken}
				err = p.EnrichSession(context.Background(), session)

				if in.expectedError != nil {
					Expect(err).To(Equal(in.expectedError))
				} else {
					Expect(err).To(BeNil())
				}

				Expect(session.Email).To(Equal(in.expectedEmail))

				if in.expectedGroups != nil {
					Expect(session.Groups).To(Equal(in.expectedGroups))
				} else {
					Expect(session.Groups).To(BeNil())
				}
			},
			Entry("email and multiple groups", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"emailAddress": "michael.bland@gsa.gov",
							"groups": {
								"items": [
									{"name": "test-grp1"},
									{"name": "test-grp2"}
								]
							}
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: []string{"test-grp1", "test-grp2"},
			}),
			Entry("email and single group", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"emailAddress": "michael.bland@gsa.gov",
							"groups": {
								"items": [
									{"name": "test-grp1"}
								]
							}
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: []string{"test-grp1"},
			}),
			Entry("email and no groups", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"emailAddress": "michael.bland@gsa.gov"
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: nil,
			}),
			Entry("missing email", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"groups": {
								"items": [
									{"name": "test-grp1"},
									{"name": "test-grp2"}
								]
							}
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError: errors.New(
					"unable to extract email from userinfo endpoint: type assertion to string failed"),
				expectedEmail:  "",
				expectedGroups: []string{"test-grp1", "test-grp2"},
			}),
			Entry("request failure", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(500)
				},
				expectedError:  errors.New(`unexpected status "500": `),
				expectedEmail:  "",
				expectedGroups: nil,
			}),
		)
	})
})
