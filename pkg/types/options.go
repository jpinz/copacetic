package types

import (
	"time"

	"github.com/moby/buildkit/util/progress/progressui"
)

// Options contains common copacetic options.
type Options struct {
	// Core single image patch configuration
	Image      string
	Report     string
	PatchedTag string
	Suffix     string

	// Bulk image patch configuration
	ConfigFile string

	// Working environment
	WorkingFolder string
	Timeout       time.Duration

	// Scanner and output
	Scanner     string
	IgnoreError bool

	// Output configuration
	Format   string
	Output   string
	Progress progressui.DisplayMode

	// Buildkit connection options
	BkAddr       string
	BkCACertPath string
	BkCertPath   string
	BkKeyPath    string

	// Platform and push
	Push      bool
	Platforms []string
	Loader    string
	OCIDir    string

	// Package types and library patch level
	PkgTypes          string
	LibraryPatchLevel string

	// Toolchain patch level (e.g., Go stdlib upgrade)
	ToolchainPatchLevel string
	GoVCSURL            string

	// Generate specific
	OutputContext string

	// EOL configuration
	EOLAPIBaseURL string
	ExitOnEOL     bool

	// AttestationOutput, if set, causes Copa to generate an in-toto Statement
	// for the patched image and write it as JSON to this file path.
	// For pushed images the attestation records both the original and patched
	// image digests. For local-only images it records whatever digest information
	// is available.
	AttestationOutput string

	// CopacticVersion is the Copa release string (e.g. "v0.7.0").
	// If set it is embedded in the generated in-toto attestation.
	// It is populated by the CLI from the binary version at startup.
	CopacticVersion string
}
