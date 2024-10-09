package infinity

import (
	"context"
	"fmt"
	"net/http"

	"github.com/grafana/grafana-infinity-datasource/pkg/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

func ApplyGoogleCloudRunAuth(ctx context.Context, httpClient *http.Client, settings models.InfinitySettings, credentialsFunc func(context.Context, []byte, ...string) (*google.Credentials, error), tokenSourceFunc func(context.Context, string, ...option.ClientOption) (oauth2.TokenSource, error)) (*http.Client, error) {
	if IsGoogleCloudRunAuthConfigured(settings) {
		audience := settings.GoogleCloudRunAudience
		if audience == "" {
			return nil, fmt.Errorf("Google Cloud Run audience is required")
		}

		var tokenSource oauth2.TokenSource
		var err error

		if settings.GoogleCloudRunServiceAccountKey != "" {
			// Use the provided service account key
			creds, err := credentialsFunc(ctx, []byte(settings.GoogleCloudRunServiceAccountKey), audience)
			if err != nil {
				return nil, fmt.Errorf("error creating credentials from JSON: %v", err)
			}
			tokenSource = creds.TokenSource
		} else {
			// Fall back to default credentials if no service account key is provided
			tokenSource, err = tokenSourceFunc(ctx, audience)
		}

		if err != nil {
			return nil, fmt.Errorf("error creating token source: %v", err)
		}

		return &http.Client{
			Transport: &oauth2.Transport{
				Base:   httpClient.Transport,
				Source: tokenSource,
			},
		}, nil
	}
	return httpClient, nil
}

func IsGoogleCloudRunAuthConfigured(settings models.InfinitySettings) bool {
	return settings.AuthenticationMethod == models.AuthenticationMethodGoogleCloudRun
}
