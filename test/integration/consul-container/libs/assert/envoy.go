package assert

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/consul/sdk/testutil/retry"
	libservice "github.com/hashicorp/consul/test/integration/consul-container/libs/service"
	"github.com/hashicorp/consul/test/integration/consul-container/libs/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GetEnvoyListenerFilters validates that proxy was configured with one rbac listener filter
func GetEnvoyListenerFilters(t *testing.T, adminPort int) {
	failer := func() *retry.Timer {
		return &retry.Timer{Timeout: 30 * time.Second, Wait: 1 * time.Second}
	}

	retry.RunWith(failer(), t, func(r *retry.R) {
		dump, err := libservice.GetEnvoyConfigDump(adminPort, "")
		if err != nil {
			r.Fatal("could not curl envoy configuration")
		}

		// Make sure there is one rbac listener listener configured
		filter := `.configs[2].dynamic_listeners[].active_state.listener | "\(.name) \( .filter_chains[0].filters | map(.name))"`
		results, err := utils.JQFilter(dump, filter)
		if err != nil {
			r.Fatal("could not parse envoy configuration")
		}

		if len(results) != 2 {
			r.Fatalf("s1 proxy should have been configured with one rbac listener filter and %d present", len(results))
		}

		// validate public listeners value
		var filteredResult []string
		rgx := regexp.MustCompile(`\[(.*?)\]`)
		for _, result := range results {
			foundString := rgx.FindStringSubmatch(result)
			sanitizedResult := sanitizeResult(foundString[1])
			filteredResult = append(filteredResult, sanitizedResult...)
		}

		require.Contains(t, filteredResult, "envoy.filters.network.rbac")
		assert.Contains(t, filteredResult, "envoy.filters.network.tcp_proxy")
	})
}

// GetEnvoyHTTPrbacFilters validates that proxy was configured with http rbac filters
func GetEnvoyHTTPrbacFilters(t *testing.T, port int) {
	failer := func() *retry.Timer {
		return &retry.Timer{Timeout: 30 * time.Second, Wait: 1 * time.Second}
	}

	retry.RunWith(failer(), t, func(r *retry.R) {
		dump, err := libservice.GetEnvoyConfigDump(port, "")
		if err != nil {
			r.Fatal("could not curl envoy configuration")
		}

		// Make sure s1 proxy has been been configured with http rbac filters
		filter := `.configs[2].dynamic_listeners[].active_state.listener | "\(.name) \( .filter_chains[0].filters[] | select(.name == "envoy.filters.network.http_connection_manager") | .typed_config.http_filters | map(.name) | join(","))"`
		results, err := utils.JQFilter(dump, filter)
		if err != nil {
			r.Fatal("%s", "could not parse envoy configuration")
		}

		if len(results) != 2 {
			r.Fatal("s1 proxy should have been configured with one rbac listener filter and %d present", len(results))
		}

		// validate public listeners value
		var filteredResult []string
		rgx := regexp.MustCompile(`\[(.*?)\]`)
		for _, result := range results {
			foundString := rgx.FindStringSubmatch(result)
			sanitizedResult := sanitizeResult(foundString[1])
			filteredResult = append(filteredResult, sanitizedResult...)
		}
		require.Contains(t, filteredResult, "envoy.filters.http.rbac")
		assert.Contains(t, filteredResult, "envoy.filters.http.header_to_metadata")
		assert.Contains(t, filteredResult, "envoy.filters.http.router")

	})
}

// sanitizeResult takes the value returned from config_dump json and cleans it up to remove special characters
func sanitizeResult(s string) []string {
	result := strings.ReplaceAll(s, `"`, "")
	result = strings.ReplaceAll(result, `,`, " ")
	return strings.Split(result, " ")
}
