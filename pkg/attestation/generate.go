package attestation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// Input contains all information required to generate a Copa patch attestation.
type Input struct {
	// CopacticVersion is the Copa release string (e.g. "v0.7.0"). May be empty.
	CopacticVersion string

	// StartedAt is the time the patch operation was initiated.
	StartedAt time.Time

	// FinishedAt is the time the patch operation completed.
	FinishedAt time.Time

	// OriginalRef is the original image reference (tag) as a string.
	OriginalRef string

	// OriginalDesc is the OCI descriptor for the original image, captured before
	// patching. It may be nil if the descriptor could not be resolved (e.g. for
	// local-only images where the tag was reused).
	OriginalDesc *ispec.Descriptor

	// PatchedRef is the output image reference (tag) as a string.
	PatchedRef string

	// PatchedDesc is the OCI descriptor of the patched image. It may be nil if
	// the descriptor could not be resolved (e.g. when the image was not pushed).
	PatchedDesc *ispec.Descriptor

	// Platform is the target platform string (e.g. "linux/amd64"). May be empty.
	Platform string

	// ReportFile is the path to the vulnerability scanner report. May be empty.
	ReportFile string

	// IgnoreError reflects the --ignore-error flag value.
	IgnoreError bool

	// PkgTypes is the comma-separated package-type filter string.
	PkgTypes string

	// Scanner is the name of the vulnerability scanner used to produce the report.
	Scanner string

	// UpdateManifest contains the update packages applied. May be nil.
	UpdateManifest *unversioned.UpdateManifest

	// PatchSummaryResult contains aggregate patch counts. May be nil.
	PatchSummaryResult *unversioned.PatchSummary

	// ErroredPackages is the list of package names that could not be updated.
	ErroredPackages []string
}

// Generate creates an in-toto Statement for the patched image described by input.
//
// The generated statement captures:
//   - The patched image as the subject (by digest when available).
//   - The original image as a material/input.
//   - Copa invocation parameters, package update details, and timestamps.
//
// The caller is responsible for writing the returned statement to the desired output
// (use WriteToFile for the common file-based fallback).
func Generate(input Input) (*Statement, error) {
	if input.PatchedRef == "" {
		return nil, fmt.Errorf("patched image reference must not be empty")
	}

	finishedAt := input.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now().UTC()
	}
	startedAt := input.StartedAt
	if startedAt.IsZero() {
		startedAt = finishedAt
	}

	// --- Build subject ---
	subject := buildSubject(input.PatchedRef, input.PatchedDesc)

	// --- Build materials ---
	materials := buildMaterials(input.OriginalRef, input.OriginalDesc)

	// --- Build patch details ---
	patchDetails := buildPatchDetails(input.PatchedRef, input.UpdateManifest, input.PatchSummaryResult, input.ErroredPackages)

	// --- Build predicate ---
	pred := CopaPatchPredicate{
		BuildType: BuildTypeURI,
		Builder: Builder{
			ID:      BuilderID,
			Version: input.CopacticVersion,
		},
		Invocation: Invocation{
			ConfigSource: ConfigSource{
				URI: BuilderID,
			},
			Parameters: InvocationParameters{
				OriginalImageRef: input.OriginalRef,
				Platform:         input.Platform,
				ReportFile:       filepath.Base(input.ReportFile),
				IgnoreError:      input.IgnoreError,
				PkgTypes:         input.PkgTypes,
				Scanner:          input.Scanner,
			},
		},
		Materials: materials,
		Metadata: BuildMetadata{
			BuildStartedOn:  startedAt,
			BuildFinishedOn: finishedAt,
			Completeness: Completeness{
				Parameters:  true,
				Materials:   input.OriginalDesc != nil,
				Environment: false,
			},
		},
		PatchDetails: patchDetails,
	}

	stmt := &Statement{
		Type:          StatementTypeV01,
		Subject:       subject,
		PredicateType: PredicateTypeCopaPatch,
		Predicate:     pred,
	}

	return stmt, nil
}

// WriteToFile marshals stmt to indented JSON and writes it to outputPath.
// Parent directories are created if they do not exist.
func WriteToFile(stmt *Statement, outputPath string) error {
	if outputPath == "" {
		return fmt.Errorf("output path must not be empty")
	}

	data, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attestation to JSON: %w", err)
	}

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create attestation output directory %s: %w", dir, err)
	}

	//nolint:gosec // output path is user-provided; permissions are intentionally readable
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write attestation to %s: %w", outputPath, err)
	}

	log.Infof("Attestation written to %s", outputPath)
	return nil
}

// GenerateAndWrite is a convenience wrapper that calls Generate followed by WriteToFile.
func GenerateAndWrite(input Input, outputPath string) error {
	stmt, err := Generate(input)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %w", err)
	}
	return WriteToFile(stmt, outputPath)
}

// BuildAttestationInput constructs an attestation Input from the supplied patch result and options.
// copaVersion is the Copa binary version string (may be empty for dev builds).
func BuildAttestationInput(
	result *types.PatchResult,
	copaVersion string,
	platform string,
	reportFile string,
	ignoreError bool,
	pkgTypes string,
	scanner string,
	startedAt time.Time,
	erroredPackages []string,
) Input {
	var updateManifest *unversioned.UpdateManifest
	var patchSummary *unversioned.PatchSummary

	if result != nil && result.Summary != nil {
		patchSummary = result.Summary
	}

	input := Input{
		CopacticVersion:    copaVersion,
		StartedAt:          startedAt,
		FinishedAt:         time.Now().UTC(),
		Platform:           platform,
		ReportFile:         reportFile,
		IgnoreError:        ignoreError,
		PkgTypes:           pkgTypes,
		Scanner:            scanner,
		UpdateManifest:     updateManifest,
		PatchSummaryResult: patchSummary,
		ErroredPackages:    erroredPackages,
	}

	if result != nil {
		if result.OriginalRef != nil {
			input.OriginalRef = result.OriginalRef.String()
		}
		input.OriginalDesc = result.OriginalDesc
		if result.PatchedRef != nil {
			input.PatchedRef = result.PatchedRef.String()
		}
		input.PatchedDesc = result.PatchedDesc
	}

	return input
}

// --- internal helpers ---

func buildSubject(patchedRef string, patchedDesc *ispec.Descriptor) []Subject {
	subj := Subject{
		Name:   patchedRef,
		Digest: map[string]string{},
	}

	if patchedDesc != nil && patchedDesc.Digest != "" {
		algo := patchedDesc.Digest.Algorithm().String()
		hex := patchedDesc.Digest.Hex()
		if algo != "" && hex != "" {
			subj.Digest[algo] = hex
		}
	}

	return []Subject{subj}
}

func buildMaterials(originalRef string, originalDesc *ispec.Descriptor) []Material {
	if originalRef == "" {
		return nil
	}

	mat := Material{
		URI:    originalRef,
		Digest: map[string]string{},
	}

	if originalDesc != nil && originalDesc.Digest != "" {
		algo := originalDesc.Digest.Algorithm().String()
		hex := originalDesc.Digest.Hex()
		if algo != "" && hex != "" {
			mat.Digest[algo] = hex
		}
	}

	return []Material{mat}
}

func buildPatchDetails(
	patchedRef string,
	updateManifest *unversioned.UpdateManifest,
	summary *unversioned.PatchSummary,
	erroredPackages []string,
) PatchDetails {
	details := PatchDetails{
		PatchedImageRef: patchedRef,
		PackagesErrored: erroredPackages,
	}

	if updateManifest != nil {
		for _, u := range updateManifest.OSUpdates {
			details.PackagesUpdated = append(details.PackagesUpdated, PackageUpdate{
				Name:             u.Name,
				InstalledVersion: u.InstalledVersion,
				FixedVersion:     u.FixedVersion,
				VulnerabilityID:  u.VulnerabilityID,
				Type:             u.Type,
			})
		}
		for _, u := range updateManifest.LangUpdates {
			details.PackagesUpdated = append(details.PackagesUpdated, PackageUpdate{
				Name:             u.Name,
				InstalledVersion: u.InstalledVersion,
				FixedVersion:     u.FixedVersion,
				VulnerabilityID:  u.VulnerabilityID,
				Type:             u.Type,
			})
		}
	}

	if summary != nil {
		details.Summary = &PatchSummary{
			Total:   summary.Total,
			Patched: summary.Patched,
			Skipped: summary.Skipped,
		}
	}

	return details
}
