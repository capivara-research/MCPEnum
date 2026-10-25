package mcprecon

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "2.0"

type Config struct {
	URLs            []string
	Targets         []string
	Ports           []int
	Paths           []string
	Scheme          string // auto, http, or https for expanded targets only
	Token           string
	Insecure        bool
	Timeout         int // milliseconds per request
	Budget          int // milliseconds per endpoint
	Workers         int
	MaxPages        int
	MaxItems        int
	MaxBody         int64
	MaxHosts        int
	AllowCIDR       bool
	Rate            int // global HTTP requests per second; zero disables pacing
	gate            <-chan time.Time
	UserAgent       string
	HTTPProbe       string // off, basic, or extended; performed once per origin
	PortDiscovery   bool   // preflight selected --target ports before endpoint requests
	PortScanStart   int    // optional inclusive TCP range, scanned before endpoint expansion
	PortScanEnd     int
	PortScanWorkers int
	PortScanTimeout int                 // milliseconds per TCP connection
	Progress        func(ProgressEvent) // optional scan telemetry; callbacks may be concurrent
}

type ProgressEvent struct {
	Phase  string
	Done   int
	Total  int
	Target string
	Status string
}

type Result struct {
	SchemaVersion string        `json:"schema_version"`
	Scanner       string        `json:"scanner"`
	Target        Target        `json:"target"`
	ScanStatus    string        `json:"scan_status"`
	Services      []Service     `json:"services"`
	Observations  []Observation `json:"observations"`
	PortInfo      *PortInfo     `json:"port_info,omitempty"`
	Metrics       Metrics       `json:"metrics"`
	Warnings      []string      `json:"warnings,omitempty"`
}

type Target struct {
	Input  string `json:"input"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme,omitempty"`
}

// PortInfo records bounded HTTP observations shared by paths on one origin.
// Product and version headers are self-reported, not independently verified.
type PortInfo struct {
	Origin     string          `json:"origin"`
	TCPState   string          `json:"tcp_state"`
	TLSVersion string          `json:"tls_version,omitempty"`
	DurationMS int64           `json:"duration_ms"`
	Probes     []HTTPProbeInfo `json:"probes"`
}

type HTTPProbeInfo struct {
	Method          string `json:"method"`
	Path            string `json:"path"`
	Status          int    `json:"status,omitempty"`
	StatusText      string `json:"status_text,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Server          string `json:"server,omitempty"`
	PoweredBy       string `json:"powered_by,omitempty"`
	ContentType     string `json:"content_type,omitempty"`
	ContentLength   string `json:"content_length,omitempty"`
	Date            string `json:"date,omitempty"`
	Via             string `json:"via,omitempty"`
	Allow           string `json:"allow,omitempty"`
	Location        string `json:"location,omitempty"`
	WWWAuthenticate string `json:"www_authenticate,omitempty"`
	Title           string `json:"title,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
	ElapsedMS       int64  `json:"elapsed_ms"`
}

type Service struct {
	Kind           string         `json:"kind"`
	Endpoint       string         `json:"endpoint"`
	Detection      Detection      `json:"detection"`
	Authentication Authentication `json:"authentication"`
	MCP            MCP            `json:"mcp"`
	Findings       []Finding      `json:"findings,omitempty"`
}

type Detection struct {
	Status      string   `json:"status"`
	Confidence  string   `json:"confidence,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
	Reason      string   `json:"reason,omitempty"`
}

type Authentication struct {
	Anonymous            string   `json:"anonymous"`
	Credentialed         string   `json:"credentialed"`
	OAuthResource        string   `json:"oauth_resource,omitempty"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	EvidenceIDs          []string `json:"evidence_ids,omitempty"`
}

type MCP struct {
	Transport       string                 `json:"transport"`
	Era             string                 `json:"era"`
	Session         string                 `json:"session,omitempty"`
	ProtocolVersion string                 `json:"protocol_version,omitempty"`
	ServerName      string                 `json:"server_name,omitempty"`
	ServerVersion   string                 `json:"server_version,omitempty"`
	Capabilities    map[string]any         `json:"capabilities,omitempty"`
	Inventories     map[string]Collections `json:"inventories"`
}

type Collections struct {
	Tools             Collection `json:"tools"`
	Resources         Collection `json:"resources"`
	ResourceTemplates Collection `json:"resource_templates"`
	Prompts           Collection `json:"prompts"`
}

type Collection struct {
	Status       string           `json:"status"`
	Pages        int              `json:"pages"`
	Count        int              `json:"count"`
	Items        []map[string]any `json:"items"`
	ErrorCode    string           `json:"error_code,omitempty"`
	ErrorMessage string           `json:"error_message,omitempty"`
	EvidenceIDs  []string         `json:"evidence_ids,omitempty"`
}

type Finding struct {
	Code        string   `json:"code"`
	Summary     string   `json:"summary"`
	Status      string   `json:"status"`
	Confidence  string   `json:"confidence"`
	Category    string   `json:"category,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	SourcePath  string   `json:"source_path,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Observation struct {
	ID            string `json:"id"`
	Phase         string `json:"phase,omitempty"`
	Method        string `json:"method"`
	Path          string `json:"path,omitempty"`
	ResolvedPath  string `json:"resolved_path,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	HTTPServer    string `json:"http_server,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	RPCStatus     string `json:"rpc_status,omitempty"`
	RPCCode       int    `json:"rpc_code,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	ElapsedMS     int64  `json:"elapsed_ms"`
	BytesReceived int64  `json:"bytes_received,omitempty"`
}

type Metrics struct {
	Requests      int   `json:"requests"`
	DurationMS    int64 `json:"duration_ms"`
	TCPConnects   int   `json:"tcp_connects,omitempty"`
	BytesReceived int64 `json:"bytes_received,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}
