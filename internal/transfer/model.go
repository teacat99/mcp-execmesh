package transfer

// DownloadFileSpec represents the OpenAI ChatGPT file parameters format (_meta["openai/fileParams"]).
type DownloadFileSpec struct {
	DownloadURL string `json:"download_url"`
	FileID      string `json:"file_id"`
	MimeType    string `json:"mime_type,omitempty"`
	FileName    string `json:"file_name,omitempty"`
}

// PushRequest defines parameters for pushing a file to a remote target.
type PushRequest struct {
	Target     string           `json:"target"`
	File       DownloadFileSpec `json:"file"`
	RemotePath string           `json:"remote_path"`
	Overwrite  bool             `json:"overwrite,omitempty"`
	Mode       string           `json:"mode,omitempty"` // e.g. "0755" or "0644"
}

// PushResponse represents the result of a successful file push.
type PushResponse struct {
	Target     string `json:"target"`
	RemotePath string `json:"remote_path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Mode       string `json:"mode"`
}

// StatRequest defines parameters for querying remote file metadata.
type StatRequest struct {
	Target string `json:"target"`
	Path   string `json:"path"`
}

// StatResponse represents remote file metadata.
type StatResponse struct {
	Target string  `json:"target"`
	Path   string  `json:"path"`
	Exists bool    `json:"exists"`
	Type   string  `json:"type,omitempty"` // "file", "dir", "symlink", "other"
	Size   int64   `json:"size,omitempty"`
	Mode   string  `json:"mode,omitempty"`
	MTime  string  `json:"mtime,omitempty"`
	SHA256 *string `json:"sha256,omitempty"`
}

// HashRequest defines parameters for computing checksum of a remote file.
type HashRequest struct {
	Target    string `json:"target"`
	Path      string `json:"path"`
	Algorithm string `json:"algorithm,omitempty"` // "sha256" (default), "sha1", "md5"
}

// HashResponse represents the result of file hash calculation.
type HashResponse struct {
	Target    string `json:"target"`
	Path      string `json:"path"`
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
	Size      int64  `json:"size"`
}

// PullPrepareRequest defines parameters for preparing a one-time download URL.
type PullPrepareRequest struct {
	Target     string `json:"target"`
	Path       string `json:"path"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"` // default: 900 (15 min), max: 3600
}

// PullPrepareResponse represents the one-time download ticket.
type PullPrepareResponse struct {
	DownloadURL string `json:"download_url"`
	Target      string `json:"target"`
	Path        string `json:"path"`
	ExpiresAt   string `json:"expires_at"`
	Size        int64  `json:"size"`
}
