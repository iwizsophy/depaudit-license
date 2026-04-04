package purl

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"depaudit-license/internal/inventory"
)

type PackageURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

func Normalize(raw string) (string, bool) {
	parsed, ok := Parse(raw)
	if !ok {
		return "", false
	}
	return parsed.String(), true
}

func Parse(raw string) (PackageURL, bool) {
	value := strings.TrimSpace(raw)
	if !strings.HasPrefix(value, "pkg:") {
		return PackageURL{}, false
	}
	value = strings.TrimPrefix(value, "pkg:")

	subpath := ""
	if index := strings.Index(value, "#"); index >= 0 {
		subpath = value[index+1:]
		value = value[:index]
	}

	qualifiers := map[string]string{}
	if index := strings.Index(value, "?"); index >= 0 {
		qualifiers = parseQualifiers(value[index+1:])
		value = value[:index]
	}

	version := ""
	if index := strings.LastIndex(value, "@"); index >= 0 {
		version = value[index+1:]
		value = value[:index]
	}

	parts := strings.Split(value, "/")
	if len(parts) < 2 {
		return PackageURL{}, false
	}
	pkg := PackageURL{
		Type:       strings.ToLower(strings.TrimSpace(parts[0])),
		Name:       strings.TrimSpace(parts[len(parts)-1]),
		Version:    decode(strings.TrimSpace(version)),
		Qualifiers: qualifiers,
		Subpath:    cleanSubpath(subpath),
	}
	if len(parts) > 2 {
		pkg.Namespace = decode(strings.Join(parts[1:len(parts)-1], "/"))
	}
	pkg.Name = decode(pkg.Name)
	pkg = canonicalize(pkg)
	if pkg.Type == "" || pkg.Name == "" {
		return PackageURL{}, false
	}
	return pkg, true
}

func FromPackage(pkg inventory.Package) (string, bool) {
	if normalized, ok := Normalize(pkg.PURL); ok {
		return normalized, true
	}

	switch strings.ToLower(strings.TrimSpace(pkg.Ecosystem)) {
	case "node":
		name := strings.TrimSpace(pkg.Name)
		if name == "" {
			return "", false
		}
		namespace := ""
		if strings.HasPrefix(name, "@") {
			segments := strings.SplitN(strings.TrimPrefix(name, "@"), "/", 2)
			if len(segments) == 2 {
				namespace = segments[0]
				name = segments[1]
			}
		}
		return PackageURL{
			Type:      "npm",
			Namespace: namespace,
			Name:      name,
			Version:   strings.TrimSpace(pkg.Version),
		}.String(), true
	case "dotnet":
		if strings.TrimSpace(pkg.Name) == "" {
			return "", false
		}
		return PackageURL{
			Type:    "nuget",
			Name:    strings.TrimSpace(pkg.Name),
			Version: strings.TrimSpace(pkg.Version),
		}.String(), true
	default:
		if strings.TrimSpace(pkg.Name) == "" {
			return "", false
		}
		return PackageURL{
			Type:    canonicalGenericType(pkg.Ecosystem),
			Name:    strings.TrimSpace(pkg.Name),
			Version: strings.TrimSpace(pkg.Version),
		}.String(), true
	}
}

func (p PackageURL) String() string {
	p = canonicalize(p)
	if p.Type == "" || p.Name == "" {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("pkg:")
	builder.WriteString(p.Type)
	builder.WriteString("/")
	if p.Namespace != "" {
		builder.WriteString(encodePath(p.Namespace))
		builder.WriteString("/")
	}
	builder.WriteString(encodePath(p.Name))
	if p.Version != "" {
		builder.WriteString("@")
		builder.WriteString(url.PathEscape(p.Version))
	}
	if len(p.Qualifiers) > 0 {
		builder.WriteString("?")
		builder.WriteString(renderQualifiers(p.Qualifiers))
	}
	if p.Subpath != "" {
		builder.WriteString("#")
		builder.WriteString(encodePath(p.Subpath))
	}
	return builder.String()
}

func canonicalize(p PackageURL) PackageURL {
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	p.Namespace = strings.Trim(strings.TrimSpace(p.Namespace), "/")
	p.Name = strings.Trim(strings.TrimSpace(p.Name), "/")
	p.Version = strings.TrimSpace(p.Version)
	p.Subpath = cleanSubpath(p.Subpath)

	switch p.Type {
	case "npm":
		p.Namespace = strings.TrimPrefix(strings.ToLower(p.Namespace), "@")
		p.Name = strings.ToLower(p.Name)
	case "nuget":
		p.Namespace = ""
		p.Name = strings.ToLower(p.Name)
	default:
		p.Type = canonicalGenericType(p.Type)
	}

	if len(p.Qualifiers) > 0 {
		result := make(map[string]string, len(p.Qualifiers))
		for key, value := range p.Qualifiers {
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			if key == "" || value == "" {
				continue
			}
			result[key] = value
		}
		p.Qualifiers = result
	}
	return p
}

func canonicalGenericType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "generic"
	}
	return value
}

func parseQualifiers(raw string) map[string]string {
	values := map[string]string{}
	for _, part := range strings.Split(raw, "&") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = decode(strings.TrimSpace(value))
		if key == "" || value == "" {
			continue
		}
		values[key] = value
	}
	return values
}

func renderQualifiers(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+url.QueryEscape(values[key]))
	}
	return strings.Join(parts, "&")
}

func decode(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func encodePath(value string) string {
	segments := strings.Split(strings.Trim(value, "/"), "/")
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

func cleanSubpath(value string) string {
	return strings.Trim(strings.TrimSpace(decode(value)), "/")
}

func CanonicalKey(pkg inventory.Package) string {
	if normalized, ok := FromPackage(pkg); ok {
		return normalized
	}
	return fmt.Sprintf(
		"%s\x00%s\x00%s",
		strings.ToLower(strings.TrimSpace(pkg.Ecosystem)),
		strings.ToLower(strings.TrimSpace(pkg.Name)),
		strings.TrimSpace(pkg.Version),
	)
}
