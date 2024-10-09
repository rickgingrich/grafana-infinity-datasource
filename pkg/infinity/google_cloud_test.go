package infinity

import (
	"context"
	"net/http"
	"testing"

	"github.com/grafana/grafana-infinity-datasource/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

// MockTokenSource is a mock implementation of oauth2.TokenSource
type MockTokenSource struct{}

func (m *MockTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}

func TestApplyGoogleCloudRunAuth(t *testing.T) {
	mockCredentialsFunc := func(ctx context.Context, jsonKey []byte, scopes ...string) (*google.Credentials, error) {
		return &google.Credentials{TokenSource: &MockTokenSource{}}, nil
	}

	mockTokenSourceFunc := func(ctx context.Context, audience string, opts ...option.ClientOption) (oauth2.TokenSource, error) {
		return &MockTokenSource{}, nil
	}

	t.Run("should return original client when Google Cloud Run auth is not configured", func(t *testing.T) {
		originalClient := &http.Client{}
		settings := models.InfinitySettings{
			AuthenticationMethod: models.AuthenticationMethodNone,
		}

		resultClient, err := ApplyGoogleCloudRunAuth(context.Background(), originalClient, settings, mockCredentialsFunc, mockTokenSourceFunc)

		require.NoError(t, err)
		assert.Equal(t, originalClient, resultClient)
	})

	t.Run("should return error when audience is not set", func(t *testing.T) {
		originalClient := &http.Client{}
		settings := models.InfinitySettings{
			AuthenticationMethod: models.AuthenticationMethodGoogleCloudRun,
		}

		_, err := ApplyGoogleCloudRunAuth(context.Background(), originalClient, settings, mockCredentialsFunc, mockTokenSourceFunc)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Google Cloud Run audience is required")
	})

	t.Run("should create new client with token source when audience is set", func(t *testing.T) {
		originalClient := &http.Client{}
		settings := models.InfinitySettings{
			AuthenticationMethod:   models.AuthenticationMethodGoogleCloudRun,
			GoogleCloudRunAudience: "https://your-cloud-run-service-url",
		}

		resultClient, err := ApplyGoogleCloudRunAuth(context.Background(), originalClient, settings, mockCredentialsFunc, mockTokenSourceFunc)

		require.NoError(t, err)
		assert.NotEqual(t, originalClient, resultClient)
		assert.NotNil(t, resultClient.Transport)
		_, ok := resultClient.Transport.(*oauth2.Transport)
		assert.True(t, ok)
	})

	t.Run("should use service account key when provided", func(t *testing.T) {
		originalClient := &http.Client{}
		settings := models.InfinitySettings{
			AuthenticationMethod:            models.AuthenticationMethodGoogleCloudRun,
			GoogleCloudRunAudience:          "https://your-cloud-run-service-url",
			GoogleCloudRunServiceAccountKey: "test-service-account-key",
		}

		mockCredentialsFunc := func(ctx context.Context, jsonKey []byte, scopes ...string) (*google.Credentials, error) {
			assert.Equal(t, []byte("test-service-account-key"), jsonKey)
			return &google.Credentials{TokenSource: &MockTokenSource{}}, nil
		}

		resultClient, err := ApplyGoogleCloudRunAuth(context.Background(), originalClient, settings, mockCredentialsFunc, mockTokenSourceFunc)

		require.NoError(t, err)
		assert.NotEqual(t, originalClient, resultClient)
		assert.NotNil(t, resultClient.Transport)
		_, ok := resultClient.Transport.(*oauth2.Transport)
		assert.True(t, ok)
	})
}

func TestIsGoogleCloudRunAuthConfigured(t *testing.T) {
	t.Run("should return true when Google Cloud Run auth is configured", func(t *testing.T) {
		settings := models.InfinitySettings{
			AuthenticationMethod: models.AuthenticationMethodGoogleCloudRun,
		}

		result := IsGoogleCloudRunAuthConfigured(settings)

		assert.True(t, result)
	})

	t.Run("should return false when Google Cloud Run auth is not configured", func(t *testing.T) {
		settings := models.InfinitySettings{
			AuthenticationMethod: models.AuthenticationMethodNone,
		}

		result := IsGoogleCloudRunAuthConfigured(settings)

		assert.False(t, result)
	})
}
