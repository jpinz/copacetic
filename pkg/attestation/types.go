// Package attestation provides in-toto Statement generation for Copa patch operations.
//
// After a Copa patch, a new in-toto Statement (using a Copa-specific predicate) is generated
// for the patched image. The statement captures:
//   - The patched image as the subject (by digest where available)
//   - The original image as a material/input
//   - Copa patch invocation parameters, package update details, and timestamps
//
// If the source image already had attestations those are recorded as evidence in the materials
// list so the lineage is preserved, even though the original attestation signatures cannot
// be reused for the new (patched) image digest.
//
// For pushed images the attestation is written to the file path specified by
// --attestation-output. For local-only images the same file-based mechanism is
// used as the best available fallback (OCI referrer attachment is registry-native
// and not available without a push).
package attestation

import (
	"encoding/json"
	"time"
)

const (
	// StatementTypeV01 is the in-toto Statement type URI for version 0.1.
	StatementTypeV01 = "https://in-toto.io/Statement/v0.1"

	// PredicateTypeCopaPatch is the Copa-specific predicate type URI.
	PredicateTypeCopaPatch = "https://copacetic.dev/patch/v0.1"

	// PredicateTypeCopaReport is the Copa-specific predicate type URI for a
	// vulnerability report attestation.
	PredicateTypeCopaReport = "https://copacetic.dev/vulnerability-report/v0.1"

	// BuildTypeURI identifies the build type performed by Copa.
	BuildTypeURI = "https://copacetic.dev/patch/v0.1"

	// BuilderID is the canonical identifier for the Copa builder.
	BuilderID = "https://github.com/project-copacetic/copacetic"
)

// Statement is a plain-Go representation of an in-toto Statement (v0.1).
// It is intentionally JSON-serialisable without protobuf dependencies.
//
// Reference: https://github.com/in-toto/attestation/blob/main/spec/v0.1/README.md
type Statement struct {
	// Type must always be StatementTypeV01.
	Type string `json:"_type"`

	// Subject identifies the artifact(s) the attestation applies to.
	Subject []Subject `json:"subject"`

	// PredicateType describes the schema of Predicate.
	PredicateType string `json:"predicateType"`

	// Predicate contains the attestation-specific metadata.
	Predicate CopaPatchPredicate `json:"predicate"`
}

// Subject is an artifact identified by name and a map of digest algorithms to hex values.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// CopaPatchPredicate is the Copa-specific SLSA-inspired predicate attached to the
// in-toto Statement generated for a patched image.
type CopaPatchPredicate struct {
	// BuildType URI for this predicate schema.
	BuildType string `json:"buildType"`

	// Builder identifies the software that performed the patch.
	Builder Builder `json:"builder"`

	// Invocation describes how the patch was triggered and parameterised.
	Invocation Invocation `json:"invocation"`

	// Materials are artifacts that were used as inputs to produce the patched image.
	Materials []Material `json:"materials,omitempty"`

	// Metadata holds build-time information.
	Metadata BuildMetadata `json:"metadata"`

	// PatchDetails contains patch-specific information not covered by SLSA fields.
	PatchDetails PatchDetails `json:"patchDetails"`
}

// Builder identifies the system that produced the patched image.
type Builder struct {
	// ID is the canonical URI of the builder.
	ID string `json:"id"`

	// Version is the Copa release version (e.g. "v0.7.0"). May be empty for
	// development builds.
	Version string `json:"version,omitempty"`
}

// Invocation describes the Copa invocation that produced the patched image.
type Invocation struct {
	// ConfigSource describes where the build configuration came from.
	ConfigSource ConfigSource `json:"configSource"`

	// Parameters are the Copa CLI/option parameters used for this patch run.
	Parameters InvocationParameters `json:"parameters"`
}

// ConfigSource describes the origin of the build definition.
type ConfigSource struct {
	// URI of the Copa source repository.
	URI string `json:"uri"`
}

// InvocationParameters captures the Copa options that were used for this patch run.
type InvocationParameters struct {
	// OriginalImageRef is the image reference (tag/digest) that was patched.
	OriginalImageRef string `json:"originalImageRef"`

	// Platform is the target platform (e.g. "linux/amd64").
	Platform string `json:"platform,omitempty"`

	// ReportFile is the path or name of the vulnerability scanner report, if any.
	ReportFile string `json:"reportFile,omitempty"`

	// ReportDigest is the SHA-256 hex digest of the vulnerability report file content.
	// Only set when --attestation-embed-report is used.
	ReportDigest string `json:"reportDigest,omitempty"`

	// IgnoreError indicates whether Copa was run with --ignore-error.
	IgnoreError bool `json:"ignoreError"`

	// PkgTypes lists the package-type filters applied (e.g. "os", "library").
	PkgTypes string `json:"pkgTypes,omitempty"`

	// Scanner is the vulnerability scanner that produced the report.
	Scanner string `json:"scanner,omitempty"`
}

// Material is an artifact that was used as an input to the patch build.
type Material struct {
	// URI is a reference to the artifact (image reference, file path, URL, etc.).
	URI string `json:"uri"`

	// Digest maps algorithm names to hex digests (e.g. {"sha256": "abc..."}).
	Digest map[string]string `json:"digest,omitempty"`
}

// BuildMetadata contains build-time provenance metadata.
type BuildMetadata struct {
	// BuildStartedOn is when the Copa patch operation started (RFC 3339).
	BuildStartedOn time.Time `json:"buildStartedOn"`

	// BuildFinishedOn is when the Copa patch operation completed (RFC 3339).
	BuildFinishedOn time.Time `json:"buildFinishedOn"`

	// Completeness describes which fields in this predicate are complete.
	Completeness Completeness `json:"completeness"`
}

// Completeness indicates whether each section of the predicate is fully populated.
type Completeness struct {
	// Parameters is true when all invocation parameters are recorded.
	Parameters bool `json:"parameters"`

	// Materials is true when all input materials are recorded.
	Materials bool `json:"materials"`

	// Environment is always false; Copa does not currently record its
	// full build environment.
	Environment bool `json:"environment"`
}

// PatchDetails contains Copa-specific patch outcome information.
type PatchDetails struct {
	// PatchedImageRef is the output image reference (tag/digest).
	PatchedImageRef string `json:"patchedImageRef"`

	// PackagesUpdated is the list of packages that were successfully patched.
	PackagesUpdated []PackageUpdate `json:"packagesUpdated,omitempty"`

	// PackagesErrored is the list of package names that failed to update.
	PackagesErrored []string `json:"packagesErrored,omitempty"`

	// Summary aggregates patch outcome counts.
	Summary *PatchSummary `json:"summary,omitempty"`

	// ScanReport contains the raw JSON of the vulnerability report used for
	// patching. Only populated when --attestation-embed-report is set.
	ScanReport json.RawMessage `json:"scanReport,omitempty"`
}

// PackageUpdate records a single package vulnerability that Copa addressed.
type PackageUpdate struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	VulnerabilityID  string `json:"vulnerabilityID,omitempty"`
	Type             string `json:"type,omitempty"`
}

// PatchSummary holds aggregate counters for the patch run.
type PatchSummary struct {
	Total   int `json:"total"`
	Patched int `json:"patched"`
	Skipped int `json:"skipped"`
}

// ReportPredicate is the predicate for a Copa vulnerability-report in-toto Statement.
// It wraps the raw scanner report so it can be stored as a verifiable attestation.
type ReportPredicate struct {
	// Scanner is the name of the tool that generated the report (e.g. "trivy").
	Scanner string `json:"scanner,omitempty"`

	// ReportFile is the base filename of the original report.
	ReportFile string `json:"reportFile,omitempty"`

	// Report is the raw JSON content of the vulnerability scanner report.
	Report json.RawMessage `json:"report"`
}

// ReportStatement is a plain-Go representation of an in-toto Statement (v0.1)
// whose predicate is the raw vulnerability scanner report used during patching.
type ReportStatement struct {
	// Type must always be StatementTypeV01.
	Type string `json:"_type"`

	// Subject identifies the artifact(s) the attestation applies to.
	Subject []Subject `json:"subject"`

	// PredicateType describes the schema of Predicate.
	PredicateType string `json:"predicateType"`

	// Predicate holds the scanner report.
	Predicate ReportPredicate `json:"predicate"`
}
