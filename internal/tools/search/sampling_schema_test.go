package search_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/StrangeBeeCorp/TheHiveMCP/internal/testutils"
	"github.com/StrangeBeeCorp/TheHiveMCP/internal/types"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"
)

// captureSamplingHandler records the CreateMessageRequest forwarded to the
// sampling client, then replies with a valid FilterResult JSON.
type captureSamplingHandler struct {
	mu      sync.Mutex
	last    *mcp.CreateMessageRequest
	respond string
}

func (c *captureSamplingHandler) handle(_ context.Context, request mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
	c.mu.Lock()
	requestCopy := request
	c.last = &requestCopy
	c.mu.Unlock()
	return &mcp.CreateMessageResult{
		SamplingMessage: mcp.SamplingMessage{
			Role:    mcp.RoleAssistant,
			Content: mcp.TextContent{Type: "text", Text: c.respond},
		},
		Model:      "test-model",
		StopReason: "endTurn",
	}, nil
}

func (c *captureSamplingHandler) snapshot() *mcp.CreateMessageRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// TestSamplingPathInjectsResponseSchema verifies that the sampling code path
// (utils/sampling.go) forwards the FilterResult response schema to the model
// the same way the OpenAI path does (utils/openai.go) — without it, the model
// silently omits fields like additional_queries and extra_data, since none of
// the few-shot examples or system prompt sections demonstrate them.
//
// Regression guard for strangebeecorp/TheHiveMCP issue #1.
func TestSamplingPathInjectsResponseSchema(t *testing.T) {
	testutils.SetupTestWithCleanup(t)

	cap := &captureSamplingHandler{
		respond: `{
			"raw_filters": {"_any": ""},
			"sort_by": "_createdAt",
			"sort_order": "desc",
			"num_results": 1,
			"kept_columns": ["_id", "title"],
			"extra_data": [],
			"additional_queries": []
		}`,
	}

	mcpClient := testutils.GetMCPTestClient(t, cap.handle, testutils.DummyElicitationAccept)

	_, err := mcpClient.CallTool(t.Context(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "search-entities",
			Arguments: map[string]any{
				"entity-type": types.EntityTypeCase,
				"query":       "any case",
			},
		},
	})
	require.NoError(t, err)

	captured := cap.snapshot()
	require.NotNil(t, captured, "sampling handler was never called")

	// Flatten every text the sampling model would have seen.
	var b strings.Builder
	b.WriteString(captured.SystemPrompt)
	b.WriteString("\n")
	for _, msg := range captured.Messages {
		if tc, ok := msg.Content.(mcp.TextContent); ok {
			b.WriteString(tc.Text)
			b.WriteString("\n")
		}
	}
	full := b.String()

	// These description strings come straight from the FilterResult struct's
	// jsonschema_description tags (internal/tools/search/models.go). They
	// can only appear in the prompt if a reflected JSON schema of FilterResult
	// was injected — i.e., if sampling.go is mirroring openai.go.
	const additionalQueriesDescription = "List of additional queries to perform on the results to enrich them with related data"
	const extraDataDescription = "List of additional data fields to include in the output"

	require.Contains(t, full, additionalQueriesDescription,
		"sampling request must carry the FilterResult.AdditionalQueries description "+
			"so the model knows it can emit additional_queries in its response")
	require.Contains(t, full, extraDataDescription,
		"sampling request must carry the FilterResult.ExtraData description")

	// Sanity: the top-level field names from the response schema should also
	// be present — these only show up via the injected JSON schema.
	require.Contains(t, full, `"additional_queries"`,
		"the JSON schema instruction should list additional_queries as a property")
	require.Contains(t, full, `"extra_data"`,
		"the JSON schema instruction should list extra_data as a property")
}
