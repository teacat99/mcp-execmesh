package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teacat99/mcp-execmesh/internal/security"
	"github.com/teacat99/mcp-execmesh/internal/target"
	"github.com/teacat99/mcp-execmesh/internal/transfer"
)

type mockTransferRecorder struct {
	lastPushReq *transfer.PushRequest
}

func (m *mockTransferRecorder) Push(ctx context.Context, req transfer.PushRequest) (*transfer.PushResponse, error) {
	m.lastPushReq = &req
	return &transfer.PushResponse{
		Target:     req.Target,
		RemotePath: req.RemotePath,
		Size:       2048,
		SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Mode:       req.Mode,
	}, nil
}

func (m *mockTransferRecorder) Stat(ctx context.Context, req transfer.StatRequest) (*transfer.StatResponse, error) {
	return &transfer.StatResponse{Target: req.Target, Path: req.Path, Exists: true, Size: 2048}, nil
}

func (m *mockTransferRecorder) Hash(ctx context.Context, req transfer.HashRequest) (*transfer.HashResponse, error) {
	return &transfer.HashResponse{Target: req.Target, Path: req.Path, Algorithm: "sha256", Hash: "e3b0c442"}, nil
}

func (m *mockTransferRecorder) PullPrepare(ctx context.Context, req transfer.PullPrepareRequest, publicBaseURL string) (*transfer.PullPrepareResponse, error) {
	return &transfer.PullPrepareResponse{DownloadURL: publicBaseURL + "/files/ticket-123"}, nil
}

func (m *mockTransferRecorder) ServeDownload(w http.ResponseWriter, r *http.Request, token string) error {
	return nil
}

func setupTransferTestClient(t *testing.T, recorder *mockTransferRecorder) (*mcp.ClientSession, func()) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test-execmesh-server", Version: "1.0.0"}, &mcp.ServerOptions{})
	reg := &mockRegistry{
		targets: map[string]*target.Target{
			"test-01": {
				ID:   "test-01",
				Name: "Test Node 01",
				Capabilities: target.TargetCapabilities{
					Upload: true,
				},
			},
		},
	}
	RegisterTargetsTools(server, reg)
	RegisterTransferTools(server, recorder, "https://mcp.example.com")

	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()

	// Server-side context with full Principal
	serverCtx := security.WithPrincipal(ctx, &security.Principal{
		Subject:  "test-admin",
		AuthType: "none",
	})

	serverSession, err := server.Connect(serverCtx, t1, nil)
	require.NoError(t, err)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	clientSession, err := client.Connect(ctx, t2, nil)
	require.NoError(t, err)

	cleanup := func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	}

	return clientSession, cleanup
}

func TestFilePushSchema_OpenAIFileParams(t *testing.T) {
	recorder := &mockTransferRecorder{}
	clientSession, cleanup := setupTransferTestClient(t, recorder)
	defer cleanup()

	ctx := context.Background()
	toolsResult, err := clientSession.ListTools(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, toolsResult)

	var filePushTool *mcp.Tool
	var filePushURLTool *mcp.Tool

	for _, tool := range toolsResult.Tools {
		if tool.Name == "file_push" {
			filePushTool = tool
		} else if tool.Name == "file_push_url" {
			filePushURLTool = tool
		}
	}

	// 1. Verify file_push contract
	require.NotNil(t, filePushTool, "file_push tool must be registered")

	// Verify openai/fileParams metadata
	require.NotNil(t, filePushTool.Meta, "file_push must have Meta")
	fileParams, ok := filePushTool.Meta["openai/fileParams"]
	require.True(t, ok, "file_push must have openai/fileParams in Meta")
	switch v := fileParams.(type) {
	case []any:
		require.Len(t, v, 1)
		assert.Equal(t, "file", v[0])
	case []string:
		require.Len(t, v, 1)
		assert.Equal(t, "file", v[0])
	default:
		t.Fatalf("unexpected type for openai/fileParams: %T", fileParams)
	}

	// Marshal InputSchema to JSON to inspect raw schema structure
	schemaBytes, err := json.Marshal(filePushTool.InputSchema)
	require.NoError(t, err)

	var schemaMap map[string]any
	err = json.Unmarshal(schemaBytes, &schemaMap)
	require.NoError(t, err)

	properties, ok := schemaMap["properties"].(map[string]any)
	require.True(t, ok, "schema must contain properties map")

	fileProp, ok := properties["file"].(map[string]any)
	require.True(t, ok, "file property must exist in schema")
	assert.Equal(t, "object", fileProp["type"], "file must be an object type in raw MCP schema")

	fileSubProps, ok := fileProp["properties"].(map[string]any)
	require.True(t, ok, "file object must have properties")
	assert.Contains(t, fileSubProps, "download_url")
	assert.Contains(t, fileSubProps, "file_id")
	assert.Contains(t, fileSubProps, "mime_type")
	assert.Contains(t, fileSubProps, "file_name")

	fileRequired, ok := fileProp["required"].([]any)
	require.True(t, ok, "file object must define required fields")
	var reqFields []string
	for _, r := range fileRequired {
		reqFields = append(reqFields, r.(string))
	}
	assert.ElementsMatch(t, []string{"download_url", "file_id"}, reqFields, "file required must be exactly download_url and file_id")

	// 2. Verify file_push_url contract
	require.NotNil(t, filePushURLTool, "file_push_url tool must be registered")
	if filePushURLTool.Meta != nil {
		_, hasFileParams := filePushURLTool.Meta["openai/fileParams"]
		assert.False(t, hasFileParams, "file_push_url must NOT have openai/fileParams")
	}

	urlSchemaBytes, err := json.Marshal(filePushURLTool.InputSchema)
	require.NoError(t, err)
	var urlSchemaMap map[string]any
	err = json.Unmarshal(urlSchemaBytes, &urlSchemaMap)
	require.NoError(t, err)

	urlProps, ok := urlSchemaMap["properties"].(map[string]any)
	require.True(t, ok)
	urlField, ok := urlProps["url"].(map[string]any)
	require.True(t, ok, "url property must exist in file_push_url schema")
	assert.Equal(t, "string", urlField["type"])
}

func TestFilePush_CallToolContract(t *testing.T) {
	recorder := &mockTransferRecorder{}
	clientSession, cleanup := setupTransferTestClient(t, recorder)
	defer cleanup()

	ctx := context.Background()

	// 1. Success with valid DownloadFileSpec
	res, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "file_push",
		Arguments: map[string]any{
			"target": "test-01",
			"file": map[string]any{
				"download_url": "https://example.com/report.csv",
				"file_id":      "file-abc-123",
				"mime_type":    "text/csv",
				"file_name":    "report.csv",
			},
			"remote_path": "/srv/test/report.csv",
			"overwrite":   true,
			"mode":        "0644",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.IsError)
	require.NotNil(t, recorder.lastPushReq)
	assert.Equal(t, "test-01", recorder.lastPushReq.Target)
	assert.Equal(t, "https://example.com/report.csv", recorder.lastPushReq.File.DownloadURL)
	assert.Equal(t, "file-abc-123", recorder.lastPushReq.File.FileID)
	assert.Equal(t, "/srv/test/report.csv", recorder.lastPushReq.RemotePath)

	// 2. Error: missing file_id
	res, err = clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "file_push",
		Arguments: map[string]any{
			"target": "test-01",
			"file": map[string]any{
				"download_url": "https://example.com/report.csv",
			},
			"remote_path": "/srv/test/report.csv",
		},
	})
	assert.True(t, err != nil || (res != nil && res.IsError), "missing file_id should return error or IsError: true")
	if res != nil && res.IsError && len(res.Content) > 0 {
		textObj, ok := res.Content[0].(*mcp.TextContent)
		if ok {
			assert.Contains(t, textObj.Text, "file_id")
		}
	}

	// 3. Error: missing download_url
	res, err = clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "file_push",
		Arguments: map[string]any{
			"target": "test-01",
			"file": map[string]any{
				"file_id": "file-abc-123",
			},
			"remote_path": "/srv/test/report.csv",
		},
	})
	assert.True(t, err != nil || (res != nil && res.IsError), "missing download_url should return error or IsError: true")

	// 4. Error: file is a raw string (e.g. user/model passed URL string directly to file)
	res, err = clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "file_push",
		Arguments: map[string]any{
			"target":      "test-01",
			"file":        "https://example.com/report.csv",
			"remote_path": "/srv/test/report.csv",
		},
	})
	assert.True(t, err != nil || (res != nil && res.IsError), "raw string for file parameter must fail schema validation or handler")
}

func TestFilePushURL_CallToolContract(t *testing.T) {
	recorder := &mockTransferRecorder{}
	clientSession, cleanup := setupTransferTestClient(t, recorder)
	defer cleanup()

	ctx := context.Background()

	// 1. Success with direct URL
	res, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "file_push_url",
		Arguments: map[string]any{
			"target":      "test-01",
			"url":         "https://example.com/archive.tar.gz",
			"remote_path": "/srv/test/archive.tar.gz",
			"overwrite":   false,
			"mode":        "0755",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.IsError)
	require.NotNil(t, recorder.lastPushReq)
	assert.Equal(t, "test-01", recorder.lastPushReq.Target)
	assert.Equal(t, "https://example.com/archive.tar.gz", recorder.lastPushReq.File.DownloadURL)
	assert.Equal(t, "/srv/test/archive.tar.gz", recorder.lastPushReq.RemotePath)

	// 2. Error: missing url
	res, err = clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "file_push_url",
		Arguments: map[string]any{
			"target":      "test-01",
			"remote_path": "/srv/test/archive.tar.gz",
		},
	})
	assert.True(t, err != nil || (res != nil && res.IsError), "missing url must fail")

	// 3. Error: missing remote_path
	res, err = clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "file_push_url",
		Arguments: map[string]any{
			"target": "test-01",
			"url":    "https://example.com/archive.tar.gz",
		},
	})
	assert.True(t, err != nil || (res != nil && res.IsError), "missing remote_path must fail")
}
