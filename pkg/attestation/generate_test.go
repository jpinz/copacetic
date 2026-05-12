package attestation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/reference"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

func TestGenerate_MinimalInput(t *testing.T) {
	input := Input{
		CopacticVersion: "v0.7.0",
		OriginalRef:     "docker.io/library/nginx:1.21.6",
		PatchedRef:      "docker.io/library/nginx:1.21.6-patched",
		Platform:        "linux/amd64",
		StartedAt:       time.Now().UTC(),
		FinishedAt:      time.Now().UTC(),
	}

	stmt, err := Generate(input)
	require.NoError(t, err)
	require.NotNil(t, stmt)

	assert.Equal(t, StatementTypeV01, stmt.Type)
	assert.Equal(t, PredicateTypeCopaPatch, stmt.PredicateType)

	require.Len(t, stmt.Subject, 1)
	assert.Equal(t, "docker.io/library/nginx:1.21.6-patched", stmt.Subject[0].Name)

	assert.Equal(t, BuildTypeURI, stmt.Predicate.BuildType)
	assert.Equal(t, BuilderID, stmt.Predicate.Builder.ID)
	assert.Equal(t, "v0.7.0", stmt.Predicate.Builder.Version)
	assert.Equal(t, "docker.io/library/nginx:1.21.6", stmt.Predicate.Invocation.Parameters.OriginalImageRef)
	assert.Equal(t, "linux/amd64", stmt.Predicate.Invocation.Parameters.Platform)

	require.Len(t, stmt.Predicate.Materials, 1)
	assert.Equal(t, "docker.io/library/nginx:1.21.6", stmt.Predicate.Materials[0].URI)
}

func TestGenerate_EmptyPatchedRef(t *testing.T) {
	input := Input{
		OriginalRef: "nginx:1.21.6",
		PatchedRef:  "", // intentionally empty
	}
	_, err := Generate(input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "patched image reference must not be empty")
}

func TestGenerate_WithDigests(t *testing.T) {
	origDigest := digest.NewDigestFromEncoded(digest.SHA256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	patchDigest := digest.NewDigestFromEncoded(digest.SHA256, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	input := Input{
		OriginalRef: "nginx:1.21.6",
		OriginalDesc: &ispec.Descriptor{
			Digest: origDigest,
		},
		PatchedRef: "nginx:1.21.6-patched",
		PatchedDesc: &ispec.Descriptor{
			Digest: patchDigest,
		},
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
	}

	stmt, err := Generate(input)
	require.NoError(t, err)

	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stmt.Predicate.Materials[0].Digest["sha256"])
	assert.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", stmt.Subject[0].Digest["sha256"])

	assert.True(t, stmt.Predicate.Metadata.Completeness.Materials, "materials should be complete when original digest is available")
}

func TestGenerate_WithPackageUpdates(t *testing.T) {
	input := Input{
		OriginalRef: "nginx:1.21.6",
		PatchedRef:  "nginx:1.21.6-patched",
		UpdateManifest: &unversioned.UpdateManifest{
			OSUpdates: []unversioned.UpdatePackage{
				{
					Name:             "libssl1.1",
					InstalledVersion: "1.1.1k-1",
					FixedVersion:     "1.1.1n-1",
					VulnerabilityID:  "CVE-2022-0778",
					Type:             "deb",
				},
			},
		},
		PatchSummaryResult: &unversioned.PatchSummary{
			Total:   5,
			Patched: 4,
			Skipped: 1,
		},
		ErroredPackages: []string{"libfoo"},
		StartedAt:       time.Now().UTC(),
		FinishedAt:      time.Now().UTC(),
	}

	stmt, err := Generate(input)
	require.NoError(t, err)

	require.Len(t, stmt.Predicate.PatchDetails.PackagesUpdated, 1)
	assert.Equal(t, "libssl1.1", stmt.Predicate.PatchDetails.PackagesUpdated[0].Name)
	assert.Equal(t, "CVE-2022-0778", stmt.Predicate.PatchDetails.PackagesUpdated[0].VulnerabilityID)

	require.Len(t, stmt.Predicate.PatchDetails.PackagesErrored, 1)
	assert.Equal(t, "libfoo", stmt.Predicate.PatchDetails.PackagesErrored[0])

	require.NotNil(t, stmt.Predicate.PatchDetails.Summary)
	assert.Equal(t, 5, stmt.Predicate.PatchDetails.Summary.Total)
	assert.Equal(t, 4, stmt.Predicate.PatchDetails.Summary.Patched)
	assert.Equal(t, 1, stmt.Predicate.PatchDetails.Summary.Skipped)
}

func TestGenerate_Completeness(t *testing.T) {
	t.Run("materials incomplete without original descriptor", func(t *testing.T) {
		input := Input{
			OriginalRef: "nginx:1.21.6",
			PatchedRef:  "nginx:1.21.6-patched",
			// OriginalDesc is nil
		}
		stmt, err := Generate(input)
		require.NoError(t, err)
		assert.False(t, stmt.Predicate.Metadata.Completeness.Materials)
		assert.True(t, stmt.Predicate.Metadata.Completeness.Parameters)
		assert.False(t, stmt.Predicate.Metadata.Completeness.Environment)
	})

	t.Run("materials complete with original descriptor", func(t *testing.T) {
		d := digest.NewDigestFromEncoded(digest.SHA256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		input := Input{
			OriginalRef:  "nginx:1.21.6",
			OriginalDesc: &ispec.Descriptor{Digest: d},
			PatchedRef:   "nginx:1.21.6-patched",
		}
		stmt, err := Generate(input)
		require.NoError(t, err)
		assert.True(t, stmt.Predicate.Metadata.Completeness.Materials)
	})
}

func TestGenerate_JSONRoundtrip(t *testing.T) {
	input := Input{
		CopacticVersion: "v0.7.0",
		OriginalRef:     "nginx:1.21.6",
		PatchedRef:      "nginx:1.21.6-patched",
		Platform:        "linux/amd64",
		ReportFile:      "/tmp/trivy.json",
		IgnoreError:     false,
		PkgTypes:        "os",
		Scanner:         "trivy",
		StartedAt:       time.Now().UTC().Truncate(time.Second),
		FinishedAt:      time.Now().UTC().Truncate(time.Second),
	}

	stmt, err := Generate(input)
	require.NoError(t, err)

	data, err := json.MarshalIndent(stmt, "", "  ")
	require.NoError(t, err)

	var roundtripped Statement
	require.NoError(t, json.Unmarshal(data, &roundtripped))

	assert.Equal(t, stmt.Type, roundtripped.Type)
	assert.Equal(t, stmt.PredicateType, roundtripped.PredicateType)
	assert.Equal(t, stmt.Subject[0].Name, roundtripped.Subject[0].Name)
	assert.Equal(t, stmt.Predicate.Builder.ID, roundtripped.Predicate.Builder.ID)
	assert.Equal(t, stmt.Predicate.Invocation.Parameters.OriginalImageRef, roundtripped.Predicate.Invocation.Parameters.OriginalImageRef)
	// ReportFile should be just the base name
	assert.Equal(t, "trivy.json", roundtripped.Predicate.Invocation.Parameters.ReportFile)
}

func TestWriteToFile(t *testing.T) {
	input := Input{
		OriginalRef: "nginx:1.21.6",
		PatchedRef:  "nginx:1.21.6-patched",
	}

	stmt, err := Generate(input)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "attestation.json")

	require.NoError(t, WriteToFile(stmt, outputPath))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), StatementTypeV01)
	assert.Contains(t, string(data), PredicateTypeCopaPatch)
}

func TestWriteToFile_EmptyPath(t *testing.T) {
	stmt := &Statement{Type: StatementTypeV01}
	err := WriteToFile(stmt, "")
	assert.Error(t, err)
}

func TestWriteToFile_CreatesParentDirs(t *testing.T) {
	input := Input{
		OriginalRef: "nginx:1.21.6",
		PatchedRef:  "nginx:1.21.6-patched",
	}
	stmt, err := Generate(input)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "nested", "dir", "attestation.json")

	require.NoError(t, WriteToFile(stmt, outputPath))
	_, err = os.Stat(outputPath)
	require.NoError(t, err)
}

func TestGenerateAndWrite(t *testing.T) {
	input := Input{
		OriginalRef: "nginx:1.21.6",
		PatchedRef:  "nginx:1.21.6-patched",
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "attestation.json")

	require.NoError(t, GenerateAndWrite(input, outputPath))

	_, err := os.Stat(outputPath)
	require.NoError(t, err)
}

func TestBuildAttestationInput(t *testing.T) {
	origRef, err := reference.ParseNormalizedNamed("nginx:1.21.6")
	require.NoError(t, err)

	patchedRef, err := reference.ParseNormalizedNamed("nginx:1.21.6-patched")
	require.NoError(t, err)

	origDigest := digest.NewDigestFromEncoded(digest.SHA256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	patchDigest := digest.NewDigestFromEncoded(digest.SHA256, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	result := &types.PatchResult{
		OriginalRef:  origRef,
		OriginalDesc: &ispec.Descriptor{Digest: origDigest},
		PatchedRef:   patchedRef,
		PatchedDesc:  &ispec.Descriptor{Digest: patchDigest},
		Summary: &unversioned.PatchSummary{
			Total:   3,
			Patched: 3,
			Skipped: 0,
		},
	}

	startedAt := time.Now().UTC()
	input := BuildAttestationInput(
		result,
		"v0.7.0",
		"linux/amd64",
		"trivy.json",
		false,
		"os",
		"trivy",
		startedAt,
		[]string{"libfailed"},
	)

	assert.Equal(t, "v0.7.0", input.CopacticVersion)
	assert.Equal(t, origRef.String(), input.OriginalRef)
	assert.Equal(t, patchedRef.String(), input.PatchedRef)
	assert.Equal(t, "linux/amd64", input.Platform)
	assert.Equal(t, "trivy.json", input.ReportFile)
	assert.Equal(t, false, input.IgnoreError)
	assert.Equal(t, "os", input.PkgTypes)
	assert.Equal(t, "trivy", input.Scanner)
	assert.Equal(t, startedAt, input.StartedAt)
	assert.Equal(t, []string{"libfailed"}, input.ErroredPackages)
	assert.Equal(t, origDigest, input.OriginalDesc.Digest)
	assert.Equal(t, patchDigest, input.PatchedDesc.Digest)
	assert.NotNil(t, input.PatchSummaryResult)
	assert.Equal(t, 3, input.PatchSummaryResult.Total)
}

func TestBuildAttestationInput_NilResult(t *testing.T) {
	input := BuildAttestationInput(
		nil, // nil result
		"v0.7.0",
		"linux/amd64",
		"",
		false,
		"os",
		"trivy",
		time.Now(),
		nil,
	)

	// Should not panic; refs will be empty strings
	assert.Equal(t, "", input.OriginalRef)
	assert.Equal(t, "", input.PatchedRef)
	assert.Nil(t, input.OriginalDesc)
	assert.Nil(t, input.PatchedDesc)
}
