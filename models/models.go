package models

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"time"
)

// User represents a registered user
type User struct {
	ID          string    `json:"id"`
	FirebaseUID string    `json:"firebase_uid,omitempty"`
	Email       string    `json:"email"`
	Password    string    `json:"-"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	IsBetaUser  bool      `json:"is_beta_user"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserConfig represents user access control and quota settings
type UserConfig struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"user_id"`
	PlanID              string     `json:"plan_id"`
	PlanTier            string     `json:"plan_tier"`
	DailyScanLimit      int        `json:"daily_scan_limit"`
	IsLimited           bool       `json:"is_limited"`
	MaxFileSizeMB       int        `json:"max_file_size_mb"`
	ReportRetentionDays int        `json:"report_retention_days"`
	CanExportReports    bool       `json:"can_export_reports"`
	CanAccessAPI        bool       `json:"can_access_api"`
	TeamID              *string    `json:"team_id,omitempty"`
	SubscriptionStatus  string     `json:"subscription_status"`
	SubscriptionEndDate *time.Time `json:"subscription_end_date,omitempty"`
	PaymentAmountCents  int64      `json:"payment_amount_cents"`
	BillingCycle        string     `json:"billing_cycle"`
	LastPaymentDate     *time.Time `json:"last_payment_date,omitempty"`
	RenewalDate         *time.Time `json:"renewal_date,omitempty"`
	ActivatedAt         *time.Time `json:"activated_at,omitempty"`
	CanceledAt          *time.Time `json:"canceled_at,omitempty"`
	IsActive            bool       `json:"is_active"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// Analysis represents an APK analysis job
type Analysis struct {
	ID            string         `json:"id"`
	UserID        string         `json:"user_id"`
	FileName      string         `json:"file_name"`
	FileSize      int64          `json:"file_size"`
	Status        AnalysisStatus `json:"status"`
	Progress      int            `json:"progress"`
	ErrorMsg      string         `json:"error_msg,omitempty"`
	FailureReason string         `json:"failure_reason,omitempty"`
	Results       *Results       `json:"results,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	StartedAt     *time.Time     `json:"started_at,omitempty"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	DurationMs    int64          `json:"duration_ms,omitempty"`
	// Technical fields for admin debugging
	ExecutionLogs    []string          `json:"execution_logs,omitempty"`
	TechnicalDetails *TechnicalDetails `json:"technical_details,omitempty"`
}

type AnalysisStatus string

const (
	StatusPending    AnalysisStatus = "pending"
	StatusProcessing AnalysisStatus = "processing"
	StatusCompleted  AnalysisStatus = "completed"
	StatusFailed     AnalysisStatus = "failed"
)

// TechnicalDetails contains detailed execution information for admin debugging
type TechnicalDetails struct {
	DecompilerUsed      string           `json:"decompiler_used,omitempty"`
	DecompilationTimeMs int64            `json:"decompilation_time_ms,omitempty"`
	ExtractionTimeMs    int64            `json:"extraction_time_ms,omitempty"`
	AnalysisTimeMs      int64            `json:"analysis_time_ms,omitempty"`
	APKHash             string           `json:"apk_hash,omitempty"`
	IsFlutterApp        bool             `json:"is_flutter_app"`
	LibAppSizeBytes     int64            `json:"libapp_size_bytes,omitempty"`
	DecompiledSizeBytes int64            `json:"decompiled_size_bytes,omitempty"`
	WorkerID            int              `json:"worker_id,omitempty"`
	MemoryUsageMB       float64          `json:"memory_usage_mb,omitempty"`
	CPUTimeMs           int64            `json:"cpu_time_ms,omitempty"`
	StageTimings        map[string]int64 `json:"stage_timings,omitempty"`
	Errors              []string         `json:"errors,omitempty"`
	Warnings            []string         `json:"warnings,omitempty"`
}

// Results contains all extracted information
type Results struct {
	Emails                   []string                 `json:"emails,omitempty"`
	Domains                  []string                 `json:"domains,omitempty"`
	IPAddresses              []string                 `json:"ip_addresses,omitempty"`
	URLs                     URLCollection            `json:"urls,omitempty"`
	PhoneNumbers             []string                 `json:"phone_numbers,omitempty"`
	APIEndpoints             []Endpoint               `json:"api_endpoints,omitempty"`
	EndpointsNoDomain        []string                 `json:"endpoints_no_domain,omitempty"`
	PotentialEndpointsFull   []string                 `json:"potential_endpoints_full,omitempty"`
	PotentialEndpointsRoutes []string                 `json:"potential_endpoints_routes,omitempty"`
	HardcodedKeys            []string                 `json:"hardcoded_keys,omitempty"`
	InstallSourceHints       []string                 `json:"install_source_hints,omitempty"`
	EnvironmentHints         []string                 `json:"environment_hints,omitempty"`
	CDNUsage                 []string                 `json:"cdn_usage,omitempty"`
	HTTPRequests             []HTTPRequest            `json:"http_requests,omitempty"`
	RequestHeaders           []RequestHeader          `json:"request_headers,omitempty"`
	MethodChannels           []string                 `json:"method_channels,omitempty"`
	Packages                 []Package                `json:"packages,omitempty"`
	Imports                  []string                 `json:"imports,omitempty"`
	Permissions              []Permission             `json:"permissions,omitempty"`
	DebugInfo                *DebugInfo               `json:"debug_info,omitempty"`
	Firebase                 *FirebaseInfo            `json:"firebase,omitempty"`
	Services                 []ServiceUsage           `json:"services,omitempty"`
	SQLCommands              []string                 `json:"sql_commands,omitempty"`
	SQLiteDatabases          []string                 `json:"sqlite_databases,omitempty"`
	EnvFiles                 []FileInfo               `json:"env_files,omitempty"`
	EnvData                  []EnvFileData            `json:"env_data,omitempty"`
	CDNs                     []CDNInfo                `json:"cdns,omitempty"`
	UILibraries              []UILibrary              `json:"ui_libraries,omitempty"`
	ConfigFiles              []FileInfo               `json:"config_files,omitempty"`
	ContentFiles             []FileInfo               `json:"content_files,omitempty"`
	VisualAssets             []FileInfo               `json:"visual_assets,omitempty"`
	AssetSizes               *AssetSizeBreakdown      `json:"asset_sizes,omitempty"`
	FileTypes                *FileTypeSummary         `json:"file_types,omitempty"`
	UIComponents             *UIComponentInfo         `json:"ui_components,omitempty"`
	SDKBloat                 []SDKImpact              `json:"sdk_bloat,omitempty"`
	AppPackageName           string                   `json:"app_package_name,omitempty"`
	AppPackagePaths          []string                 `json:"app_package_paths,omitempty"`
	AppInfo                  AppMetadata              `json:"app_info,omitempty"`
	Fingerprints             *BinaryFingerprints      `json:"fingerprints,omitempty"`
	DecompiledFolderPath     string                   `json:"decompiled_folder_path,omitempty"`
	DecompiledDirPath        string                   `json:"-"`
	DecompilerUsed           string                   `json:"decompiler_used,omitempty"`
	DecompilationAttempts    []DecompilationAttempt   `json:"decompilation_attempts,omitempty"`
	AAPT2Metadata            *AAPT2Metadata           `json:"aapt2_metadata,omitempty"`
	CertificateInfo          *CertificateInfo         `json:"certificate_info,omitempty"`
	NetworkSecurity          *NetworkSecurityConfig   `json:"network_security,omitempty"`
	DataStorage              *DataStorageAnalysis     `json:"data_storage,omitempty"`
	WebViewSecurity          *WebViewSecurityAnalysis `json:"webview_security,omitempty"`
	Obfuscation              *ObfuscationAnalysis     `json:"obfuscation,omitempty"`
	DeepLinks                *DeepLinkAnalysis        `json:"deep_links,omitempty"`
	SDKAnalysis              *SDKAnalysis             `json:"sdk_analysis,omitempty"`
	Summary                  AnalysisSummary          `json:"summary"`
}

// DecompilationAttempt captures each strategy attempt for transparency
type DecompilationAttempt struct {
	Strategy string   `json:"strategy"`
	Success  bool     `json:"success"`
	Error    string   `json:"error,omitempty"`
	Logs     []string `json:"logs,omitempty"`
}

type URLCollection struct {
	HTTP    []string `json:"http,omitempty"`
	HTTPS   []string `json:"https,omitempty"`
	FTP     []string `json:"ftp,omitempty"`
	WS      []string `json:"ws,omitempty"`
	WSS     []string `json:"wss,omitempty"`
	File    []string `json:"file,omitempty"`
	Content []string `json:"content,omitempty"`
	Other   []string `json:"other,omitempty"`
}

type Endpoint struct {
	URL    string `json:"url"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
	Method string `json:"method,omitempty"`
}

type HTTPRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type RequestHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Dangerous   bool   `json:"dangerous"`
}

type Package struct {
	Name                string   `json:"name"`
	URL                 string   `json:"url"`
	Version             string   `json:"version,omitempty"`
	GrantedPoints       int      `json:"granted_points,omitempty"`
	MaxPoints           int      `json:"max_points,omitempty"`
	LikeCount           int      `json:"like_count,omitempty"`
	DownloadCount30Days int      `json:"download_count_30_days,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	Description         string   `json:"description,omitempty"`
}

type FileInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type AppMetadata struct {
	PackageName       string   `json:"package_name,omitempty"`
	VersionName       string   `json:"version_name,omitempty"`
	VersionCode       string   `json:"version_code,omitempty"`
	MinSDKVersion     string   `json:"min_sdk_version,omitempty"`
	TargetSDK         string   `json:"target_sdk,omitempty"`
	FlutterVersion    string   `json:"flutter_version,omitempty"`
	DartVersion       string   `json:"dart_version,omitempty"`
	APKSize           int64    `json:"apk_size"`
	BuildTimestamp    string   `json:"build_timestamp,omitempty"`
	SigningScheme     string   `json:"signing_scheme,omitempty"`
	IsDebugBuild      bool     `json:"is_debug_build"`
	SupportedABIs     []string `json:"supported_abis,omitempty"`
	FlutterEngineHash string   `json:"flutter_engine_hash,omitempty"`
	ImpellerEnabled   bool     `json:"impeller_enabled"`
	ExtractedTexts    []string `json:"extracted_texts,omitempty"`
	MonetizationSDKs  []string `json:"monetization_sdks,omitempty"`
	AppIconPath       string   `json:"app_icon_path,omitempty"`
}

type DebugInfo struct {
	ManifestDebuggable bool     `json:"manifest_debuggable"`
	Indicators         []string `json:"indicators,omitempty"`
}

type FirebaseInfo struct {
	Detected      bool     `json:"detected"`
	ProjectID     string   `json:"project_id,omitempty"`
	StorageBucket string   `json:"storage_bucket,omitempty"`
	APIKeyMasked  string   `json:"api_key_masked,omitempty"`
	Indicators    []string `json:"indicators,omitempty"`
	Endpoints     []string `json:"endpoints,omitempty"`
}

type ServiceUsage struct {
	Name       string   `json:"name"`
	Domains    []string `json:"domains,omitempty"`
	Packages   []string `json:"packages,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	Indicators []string `json:"indicators,omitempty"`
}

type AssetSizeBreakdown struct {
	ImagesBytes int64 `json:"images_bytes"`
	FontsBytes  int64 `json:"fonts_bytes"`
	AudioBytes  int64 `json:"audio_bytes"`
	VideoBytes  int64 `json:"video_bytes"`
	OtherBytes  int64 `json:"other_bytes"`
}

type FileTypeAggregate struct {
	Count      int   `json:"count"`
	TotalBytes int64 `json:"total_bytes"`
}

type TopExtension struct {
	Extension  string `json:"extension"`
	Count      int    `json:"count"`
	TotalBytes int64  `json:"total_bytes"`
}

type FileTypeSummary struct {
	TotalFiles       int                          `json:"total_files"`
	UniqueExtensions int                          `json:"unique_extensions"`
	TotalBytes       int64                        `json:"total_bytes"`
	AverageSizeBytes float64                      `json:"average_size_bytes"`
	ByExtension      map[string]FileTypeAggregate `json:"by_extension"`
	TopExtensions    []TopExtension               `json:"top_extensions"`
	LargestFiles     []FileInfo                   `json:"-"`
}

type BinaryFingerprints struct {
	APKSHA256    string `json:"apk_sha256,omitempty"`
	LibappSHA256 string `json:"libapp_sha256,omitempty"`
}

// AAPT2Metadata contains metadata extracted using aapt2 command
type AAPT2Metadata struct {
	PackageName      string            `json:"package_name,omitempty"`
	Permissions      []string          `json:"permissions,omitempty"`
	ExtractedStrings []string          `json:"extracted_strings,omitempty"`
	Badging          *AAPT2BadgingInfo `json:"badging,omitempty"`
}

// AAPT2BadgingInfo contains parsed output from aapt2 dump badging
type AAPT2BadgingInfo struct {
	PackageName               string            `json:"package_name,omitempty"`
	VersionCode               string            `json:"version_code,omitempty"`
	VersionName               string            `json:"version_name,omitempty"`
	PlatformBuildVersionName  string            `json:"platform_build_version_name,omitempty"`
	PlatformBuildVersionCode  string            `json:"platform_build_version_code,omitempty"`
	CompileSdkVersion         string            `json:"compile_sdk_version,omitempty"`
	CompileSdkVersionCodename string            `json:"compile_sdk_version_codename,omitempty"`
	MinSdkVersion             string            `json:"min_sdk_version,omitempty"`
	TargetSdkVersion          string            `json:"target_sdk_version,omitempty"`
	ApplicationLabel          string            `json:"application_label,omitempty"`
	ApplicationIcons          map[string]string `json:"application_icons,omitempty"`
	LaunchableActivity        string            `json:"launchable_activity,omitempty"`
	UsesPermissions           []string          `json:"uses_permissions,omitempty"`
	UsesFeatures              []string          `json:"uses_features,omitempty"`
	NativeCode                []string          `json:"native_code,omitempty"`
	Locales                   []string          `json:"locales,omitempty"`
	Densities                 []string          `json:"densities,omitempty"`
	SupportsScreens           []string          `json:"supports_screens,omitempty"`
	SupportsAnyDensity        string            `json:"supports_any_density,omitempty"`
	RawOutput                 string            `json:"raw_output,omitempty"`
}

// CertificateInfo contains information about APK certificates
type CertificateInfo struct {
	Certificates  []Certificate `json:"certificates"`
	SecurityNotes []string      `json:"security_notes,omitempty"`
	Errors        []string      `json:"errors,omitempty"`
}

// Certificate represents a single certificate from the APK
type Certificate struct {
	FileName           string `json:"file_name"`
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	CommonName         string `json:"common_name,omitempty"`
	Organization       string `json:"organization,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	ValidFrom          string `json:"valid_from"`
	ValidTo            string `json:"valid_to"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	PublicKeySize      string `json:"public_key_size,omitempty"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	IsExpired          bool   `json:"is_expired"`
	RawOutput          string `json:"raw_output,omitempty"`
}

type UIComponentInfo struct {
	Libraries   []string `json:"libraries,omitempty"`
	LottieFiles []string `json:"lottie_files,omitempty"`
	LottieCount int      `json:"lottie_count"`
}

// NetworkSecurityConfig contains network security configuration analysis
type NetworkSecurityConfig struct {
	ConfigFound        bool     `json:"config_found"`
	CleartextAllowed   bool     `json:"cleartext_allowed"`
	CertificatePinning bool     `json:"certificate_pinning"`
	TrustsUserCerts    bool     `json:"trusts_user_certs"`
	TrustsSystemCerts  bool     `json:"trusts_system_certs"`
	ConfiguredDomains  []string `json:"configured_domains,omitempty"`
	Risks              []string `json:"risks,omitempty"`
	SecurityFeatures   []string `json:"security_features,omitempty"`
	RawXML             string   `json:"raw_xml,omitempty"`
}

// StoragePattern represents a detected storage pattern
type StoragePattern struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	IsSecure    bool   `json:"is_secure"`
	IsRisky     bool   `json:"is_risky"`
}

// DataStorageAnalysis analyzes data storage patterns
type DataStorageAnalysis struct {
	Patterns           []StoragePattern `json:"patterns,omitempty"`
	DatabaseEncryption bool             `json:"database_encryption"`
	BackupAllowed      bool             `json:"backup_allowed"`
	SecurityNotes      []string         `json:"security_notes,omitempty"`
}

// WebViewSetting represents a WebView security setting
type WebViewSetting struct {
	Setting     string `json:"setting"`
	Description string `json:"description"`
	IsRisky     bool   `json:"is_risky"`
}

// WebViewSecurityAnalysis analyzes WebView security
type WebViewSecurityAnalysis struct {
	WebViewDetected  bool             `json:"webview_detected"`
	Settings         []WebViewSetting `json:"settings,omitempty"`
	SecurityFeatures []string         `json:"security_features,omitempty"`
}

// ObfuscationAnalysis analyzes code obfuscation
type ObfuscationAnalysis struct {
	ProGuardDetected  bool     `json:"proguard_detected"`
	MappingFileFound  bool     `json:"mapping_file_found"`
	LikelyObfuscated  bool     `json:"likely_obfuscated"`
	ShortClassNames   int      `json:"short_class_names"`
	StringEncryption  bool     `json:"string_encryption"`
	NativeObfuscation bool     `json:"native_obfuscation"`
	Indicators        []string `json:"indicators,omitempty"`
}

// DeepLinkAnalysis extracts deep link configuration
type DeepLinkAnalysis struct {
	Schemes          []string `json:"schemes,omitempty"`
	Hosts            []string `json:"hosts,omitempty"`
	Paths            []string `json:"paths,omitempty"`
	ExampleLinks     []string `json:"example_links,omitempty"`
	AppLinksVerified bool     `json:"app_links_verified"`
	SecurityNotes    []string `json:"security_notes,omitempty"`
}

// SDKInfo represents information about a detected SDK
type SDKInfo struct {
	Name               string   `json:"name"`
	Category           string   `json:"category"`
	Vendor             string   `json:"vendor"`
	PrivacyImpact      string   `json:"privacy_impact"`
	DataCollected      []string `json:"data_collected,omitempty"`
	RequiresCompliance []string `json:"requires_compliance,omitempty"`
	Detected           bool     `json:"detected"`
}

// SDKAnalysis provides detailed SDK analysis with privacy impact
type SDKAnalysis struct {
	Categories             map[string][]SDKInfo `json:"categories,omitempty"`
	TotalSDKs              int                  `json:"total_sdks"`
	HighPrivacyImpactCount int                  `json:"high_privacy_impact_count"`
	PrivacyScore           int                  `json:"privacy_score"`
}

type SDKImpact struct {
	Name         string  `json:"name"`
	SizeBytes    int64   `json:"size_bytes"`
	SizeMB       float64 `json:"size_mb"`
	PercentTotal float64 `json:"percent_total"`
}

type AnalysisSummary struct {
	TotalEmails            int   `json:"total_emails"`
	TotalDomains           int   `json:"total_domains"`
	TotalURLs              int   `json:"total_urls"`
	TotalPhoneNumbers      int   `json:"total_phone_numbers"`
	TotalAPIEndpoints      int   `json:"total_api_endpoints"`
	TotalEndpointsNoDomain int   `json:"total_endpoints_no_domain"`
	TotalHTTPRequests      int   `json:"total_http_requests"`
	TotalRequestHeaders    int   `json:"total_request_headers"`
	TotalMethodChannels    int   `json:"total_method_channels"`
	TotalPackages          int   `json:"total_packages"`
	TotalImports           int   `json:"total_imports"`
	TotalServices          int   `json:"total_services"`
	TotalPermissions       int   `json:"total_permissions"`
	DangerousPermissions   int   `json:"dangerous_permissions"`
	TotalEnvFiles          int   `json:"total_env_files"`
	TotalConfigFiles       int   `json:"total_config_files"`
	TotalContentFiles      int   `json:"total_content_files"`
	TotalVisualAssets      int   `json:"total_visual_assets"`
	TotalFiles             int   `json:"total_files"`
	UniqueExtensions       int   `json:"unique_extensions"`
	TotalFileBytes         int64 `json:"total_file_bytes"`
	HasSQLCommands         bool  `json:"has_sql_commands"`
	HasSQLiteDatabases     bool  `json:"has_sqlite_databases"`
}

// EnvVariable represents a key-value pair from .env files
type EnvVariable struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	IsMasked bool   `json:"is_masked"`
	FilePath string `json:"file_path"`
}

// EnvFileData contains extracted .env file information
type EnvFileData struct {
	FilePath  string        `json:"file_path"`
	Variables []EnvVariable `json:"variables"`
}

// CDNInfo represents detected CDN usage
type CDNInfo struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Endpoints []string `json:"endpoints,omitempty"`
}

// UILibrary represents detected UI libraries
type UILibrary struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	Files          []string `json:"files,omitempty"`
	PackageVersion string   `json:"package_version,omitempty"`
}

// RemediationGuide contains actionable guidance for addressing security findings
type RemediationGuide struct {
	Title    string   `json:"title"`
	Risk     string   `json:"risk"`
	Steps    []string `json:"steps"`
	Severity string   `json:"severity"`
}

// UserFeedback represents feedback or issue reports from users
type UserFeedback struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	AnalysisID   *string   `json:"analysis_id,omitempty"`
	Subject      string    `json:"subject"`
	Message      string    `json:"message"`
	FeedbackType string    `json:"feedback_type"`
	CreatedAt    time.Time `json:"created_at"`
}

// Implement sql.Scanner and driver.Valuer for Results to store as JSONB
func (r *Results) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, r)
}

func (r Results) Value() (driver.Value, error) {
	if r.Emails == nil && r.URLs.HTTP == nil {
		return nil, nil
	}

	jsonBytes, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	sanitized := bytes.ReplaceAll(jsonBytes, []byte("\x00"), []byte(""))

	sanitizedStr := strings.ReplaceAll(string(sanitized), "\\u0000", "")

	return sanitizedStr, nil
}

// API request/response types
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Name     string `json:"name" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// API request types
type SendFeedbackRequest struct {
	Subject      string  `json:"subject" binding:"required"`
	Message      string  `json:"message" binding:"required"`
	FeedbackType string  `json:"feedback_type" binding:"required"`
	AnalysisID   *string `json:"analysis_id,omitempty"`
}

type GetRemediationRequest struct {
	FindingType string `json:"finding_type" binding:"required"`
}

// PlanLimits defines the limits for a subscription plan
type PlanLimits struct {
	DailyScans       interface{} `json:"daily_scans"`
	MaxFileSize      interface{} `json:"max_file_size"`
	ReportRetention  interface{} `json:"report_retention"`
	APIAccess        bool        `json:"api_access"`
	PrioritySupport  bool        `json:"priority_support"`
	ExportReports    bool        `json:"export_reports"`
	ScanHistory      bool        `json:"scan_history"`
	AdvancedAnalysis bool        `json:"advanced_analysis"`
	CICDIntegration  bool        `json:"cicd_integration"`
	TeamSeats        interface{} `json:"team_seats"`
	OnPremise        bool        `json:"on_premise,omitempty"`
	SSOSaml          bool        `json:"sso_saml,omitempty"`
	WhiteLabel       bool        `json:"white_label,omitempty"`
}

// PlanBadge represents a visual badge for a plan
type PlanBadge struct {
	Text  string `json:"text"`
	Color string `json:"color"`
}

// Plan represents a subscription plan
type Plan struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	DisplayName         string     `json:"display_name"`
	Description         string     `json:"description"`
	Price               string     `json:"price"`
	PriceAnnual         string     `json:"price_annual,omitempty"`
	Limits              PlanLimits `json:"limits"`
	Features            []string   `json:"features"`
	Badge               *PlanBadge `json:"badge,omitempty"`
	StripePriceID       string     `json:"stripe_price_id,omitempty"`
	StripeAnnualPriceID string     `json:"stripe_annual_price_id,omitempty"`
	ContactSales        bool       `json:"contact_sales,omitempty"`
}

// Team represents a team account
type Team struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	OwnerUserID    string    `json:"owner_user_id"`
	PlanID         string    `json:"plan_id"`
	DailyScanLimit int       `json:"daily_scan_limit"`
	MaxMembers     int       `json:"max_members"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TeamMember represents a user's membership in a team
type TeamMember struct {
	ID       string    `json:"id"`
	TeamID   string    `json:"team_id"`
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	KeyHash    string     `json:"-"`
	KeyPrefix  string     `json:"key_prefix"`
	Name       string     `json:"name"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	IsActive   bool       `json:"is_active"`
}

// API Response types for pricing
type GetPlansResponse struct {
	Plans []Plan `json:"plans"`
}

type GetUserPlanResponse struct {
	Plan       Plan       `json:"plan"`
	UserConfig UserConfig `json:"user_config"`
	Usage      UsageInfo  `json:"usage"`
}

type UsageInfo struct {
	ScansToday     int `json:"scans_today"`
	ScansRemaining int `json:"scans_remaining"`
}
