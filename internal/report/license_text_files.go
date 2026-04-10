package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type LicenseTextExportConfig struct {
	OutputDir string
	LinkBase  string
}

func ExportEmbeddedLicenseTexts(view View, cfg LicenseTextExportConfig) (View, []string, error) {
	outputDir := strings.TrimSpace(cfg.OutputDir)
	if outputDir == "" {
		return view, nil, nil
	}

	linkBase := strings.TrimSpace(filepath.ToSlash(cfg.LinkBase))
	if linkBase == "" {
		linkBase = filepath.Base(outputDir)
	}

	exported := make([]string, 0)
	for index, evidence := range view.LegalNoticeEvidence {
		if evidence.Kind != "embedded-license-text" ||
			strings.TrimSpace(evidence.Text) == "" ||
			strings.TrimSpace(evidence.LicenseFilePath) == "" {
			continue
		}

		relativePath := embeddedLicenseTextRelativePath(evidence, index)
		outputPath := filepath.Join(outputDir, filepath.FromSlash(relativePath))
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return view, nil, fmt.Errorf("create embedded license text directory: %w", err)
		}
		if err := os.WriteFile(outputPath, []byte(evidence.Text), 0o644); err != nil {
			return view, nil, fmt.Errorf("write embedded license text %s: %w", outputPath, err)
		}

		view.LegalNoticeEvidence[index].CopiedFilePath = path.Join(linkBase, relativePath)
		exported = append(exported, outputPath)
	}
	return view, exported, nil
}

func embeddedLicenseTextRelativePath(evidence LegalNoticeEvidence, index int) string {
	pkg := NoticePackageRef{}
	if len(evidence.Packages) > 0 {
		pkg = evidence.Packages[0]
	}
	return path.Join(
		safeExportPathSegment(pkg.Ecosystem),
		safeExportPathSegment(pkg.Project),
		safeExportPathSegment(pkg.Name),
		safeExportPathSegment(pkg.Version),
		embeddedLicenseTextFilename(evidence.LicenseFilePath, evidence.Text, index),
	)
}

func embeddedLicenseTextFilename(originalPath string, text string, index int) string {
	normalized := path.Clean(strings.TrimLeft(filepath.ToSlash(strings.TrimSpace(originalPath)), "/"))
	base := path.Base(normalized)
	if base == "." || base == "/" || base == "" {
		base = "LICENSE"
	}

	extension := path.Ext(base)
	stem := strings.TrimSuffix(base, extension)
	if stem == "" {
		stem = "LICENSE"
	}
	if extension != "" {
		extension = "." + safeExportPathSegment(strings.TrimPrefix(extension, "."))
	}

	sum := sha256.Sum256([]byte(text))
	hash := hex.EncodeToString(sum[:])[:8]
	return fmt.Sprintf("%s-%s-%d%s", safeExportPathSegment(stem), hash, index, extension)
}

func safeExportPathSegment(value string) string {
	segment := slug(value)
	if segment == "" {
		return "unknown"
	}
	return segment
}
