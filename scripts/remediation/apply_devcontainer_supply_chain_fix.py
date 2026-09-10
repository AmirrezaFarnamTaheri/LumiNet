#!/usr/bin/env python3
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]

EXPECTED = {
    "src/apps/daemon/internal/integrations/provision/devcontainer_vless.go": "e1c2dfb6e87ecafdea416da4e10049fd95944dac",
    "src/apps/daemon/internal/integrations/provision/devcontainer_vless_test.go": "3a66536a5004aeec214dea5e5173e18f5bfd7a6c",
    "src/apps/daemon/internal/adapters/api/handlers_provision.go": "99ea9fbda7ba89997e755b32167b0a5e88a0f845",
    "src/packages/control-ui/src/pages/Operations.tsx": "a083a9cced00f34a8e683fe784a722e259c8fbfd",
}
for rel, expected in EXPECTED.items():
    actual = subprocess.check_output(["git", "hash-object", rel], cwd=ROOT, text=True).strip()
    if actual != expected:
        raise SystemExit(f"{rel} drifted: expected {expected}, got {actual}")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = ROOT / path
    source = p.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{path}: {label}: expected exactly one match, got {count}")
    p.write_text(source.replace(old, new, 1), encoding="utf-8")

impl = "src/apps/daemon/internal/integrations/provision/devcontainer_vless.go"
replace_once(
    impl,
    "\tdevcontainerUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)\n\tdevcontainerVersion = regexp.MustCompile(`^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)\n",
    "\tdevcontainerUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)\n\tdevcontainerVersion   = regexp.MustCompile(`^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)\n\tdevcontainerBaseImage = regexp.MustCompile(`^debian:bookworm-slim@sha256:[0-9a-fA-F]{64}$`)\n\tdevcontainerSHA256    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)\n",
    "immutable-input regexes",
)
replace_once(
    impl,
    '''type VLESSDevcontainerSpec struct {
\tUUID        string `json:"uuid"`
\tXrayVersion string `json:"xray_version"`
\tPort        int    `json:"port"`
\tPath        string `json:"path"`
\tMode        string `json:"mode"`
}''',
    '''type VLESSDevcontainerSpec struct {
\tUUID              string `json:"uuid"`
\tXrayVersion       string `json:"xray_version"`
\tBaseImage         string `json:"base_image"`
\tXraySHA256AMD64   string `json:"xray_sha256_amd64"`
\tXraySHA256ARM64   string `json:"xray_sha256_arm64"`
\tPort              int    `json:"port"`
\tPath              string `json:"path"`
\tMode              string `json:"mode"`
}''',
    "spec immutable fields",
)
replace_once(
    impl,
    '''\tspec.UUID = strings.TrimSpace(spec.UUID)
\tspec.XrayVersion = strings.TrimSpace(spec.XrayVersion)
\tspec.Path = strings.TrimSpace(spec.Path)''',
    '''\tspec.UUID = strings.TrimSpace(spec.UUID)
\tspec.XrayVersion = strings.TrimSpace(spec.XrayVersion)
\tspec.BaseImage = strings.TrimSpace(spec.BaseImage)
\tspec.XraySHA256AMD64 = strings.ToLower(strings.TrimSpace(spec.XraySHA256AMD64))
\tspec.XraySHA256ARM64 = strings.ToLower(strings.TrimSpace(spec.XraySHA256ARM64))
\tspec.Path = strings.TrimSpace(spec.Path)''',
    "normalization",
)
replace_once(
    impl,
    '''\tif !strings.HasPrefix(spec.XrayVersion, "v") {
\t\tspec.XrayVersion = "v" + spec.XrayVersion
\t}
\tif spec.Port == 0 {''',
    '''\tif !strings.HasPrefix(spec.XrayVersion, "v") {
\t\tspec.XrayVersion = "v" + spec.XrayVersion
\t}
\tif !devcontainerBaseImage.MatchString(spec.BaseImage) {
\t\treturn VLESSDevcontainerBundle{}, fmt.Errorf("base_image must be debian:bookworm-slim pinned by sha256 digest")
\t}
\tif !devcontainerSHA256.MatchString(spec.XraySHA256AMD64) || !devcontainerSHA256.MatchString(spec.XraySHA256ARM64) {
\t\treturn VLESSDevcontainerBundle{}, fmt.Errorf("xray_sha256_amd64 and xray_sha256_arm64 must each be 64 hexadecimal characters")
\t}
\tif spec.Port == 0 {''',
    "immutable input validation",
)
replace_once(
    impl,
    '''\tdevcontainer := map[string]any{
\t\t"name": "LumiNet VLESS XHTTP",
\t\t"build": map[string]any{
\t\t\t"dockerfile": "Dockerfile",
\t\t\t"args":       map[string]string{"XRAY_VERSION": spec.XrayVersion},
\t\t},''',
    '''\tdevcontainer := map[string]any{
\t\t"name": "LumiNet VLESS XHTTP",
\t\t"build": map[string]any{
\t\t\t"dockerfile": "Dockerfile",
\t\t\t"args": map[string]string{
\t\t\t\t"BASE_IMAGE":         spec.BaseImage,
\t\t\t\t"XRAY_VERSION":       spec.XrayVersion,
\t\t\t\t"XRAY_SHA256_AMD64":  spec.XraySHA256AMD64,
\t\t\t\t"XRAY_SHA256_ARM64":  spec.XraySHA256ARM64,
\t\t\t},
\t\t},''',
    "devcontainer build args",
)
replace_once(
    impl,
    '''\tdockerfile := `FROM debian:bookworm-slim
ARG XRAY_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \\
    && rm -rf /var/lib/apt/lists/* \\
    && arch="$(dpkg --print-architecture)" \\
    && case "$arch" in amd64) asset="Xray-linux-64.zip" ;; arm64) asset="Xray-linux-arm64-v8a.zip" ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac \\
    && curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${asset}" -o /tmp/xray.zip \\
    && unzip /tmp/xray.zip xray -d /usr/local/bin \\
    && chmod 0755 /usr/local/bin/xray \\
    && rm /tmp/xray.zip''',
    '''\tdockerfile := `ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG XRAY_VERSION
ARG XRAY_SHA256_AMD64
ARG XRAY_SHA256_ARM64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \\
    && rm -rf /var/lib/apt/lists/* \\
    && arch="$(dpkg --print-architecture)" \\
    && case "$arch" in amd64) asset="Xray-linux-64.zip"; expected="$XRAY_SHA256_AMD64" ;; arm64) asset="Xray-linux-arm64-v8a.zip"; expected="$XRAY_SHA256_ARM64" ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac \\
    && curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${asset}" -o /tmp/xray.zip \\
    && printf '%s  %s\\n' "$expected" /tmp/xray.zip | sha256sum -c - \\
    && unzip /tmp/xray.zip xray -d /usr/local/bin \\
    && chmod 0755 /usr/local/bin/xray \\
    && rm /tmp/xray.zip''',
    "Dockerfile immutable inputs",
)
replace_once(
    impl,
    '''\t\t\t"The selected Xray release is pinned by the generated build argument.",''',
    '''\t\t\t"The Debian base image is digest-pinned and both supported Xray archives are SHA-256 verified before extraction.",''',
    "truthful note",
)

handler = "src/apps/daemon/internal/adapters/api/handlers_provision.go"
replace_once(
    handler,
    '''type VLESSDevcontainerRequest struct {
\tUUID        string `json:"uuid" binding:"required"`
\tXrayVersion string `json:"xray_version" binding:"required"`
\tPort        int    `json:"port"`
\tPath        string `json:"path"`
\tMode        string `json:"mode"`
}''',
    '''type VLESSDevcontainerRequest struct {
\tUUID            string `json:"uuid" binding:"required"`
\tXrayVersion     string `json:"xray_version" binding:"required"`
\tBaseImage       string `json:"base_image" binding:"required"`
\tXraySHA256AMD64 string `json:"xray_sha256_amd64" binding:"required"`
\tXraySHA256ARM64 string `json:"xray_sha256_arm64" binding:"required"`
\tPort            int    `json:"port"`
\tPath            string `json:"path"`
\tMode            string `json:"mode"`
}''',
    "request immutable fields",
)
replace_once(
    handler,
    '''\tbundle, err := provision.GenerateVLESSDevcontainer(provision.VLESSDevcontainerSpec{
\t\tUUID: req.UUID, XrayVersion: req.XrayVersion, Port: req.Port, Path: req.Path, Mode: req.Mode,
\t})''',
    '''\tbundle, err := provision.GenerateVLESSDevcontainer(provision.VLESSDevcontainerSpec{
\t\tUUID: req.UUID, XrayVersion: req.XrayVersion, BaseImage: req.BaseImage,
\t\tXraySHA256AMD64: req.XraySHA256AMD64, XraySHA256ARM64: req.XraySHA256ARM64,
\t\tPort: req.Port, Path: req.Path, Mode: req.Mode,
\t})''',
    "request mapping",
)

test = "src/apps/daemon/internal/integrations/provision/devcontainer_vless_test.go"
replace_once(
    test,
    '''\t\tXrayVersion: "26.3.27",
\t\tPort:        8443,''',
    '''\t\tXrayVersion:     "26.3.27",
\t\tBaseImage:       "debian:bookworm-slim@sha256:" + strings.Repeat("a", 64),
\t\tXraySHA256AMD64: strings.Repeat("b", 64),
\t\tXraySHA256ARM64: strings.Repeat("c", 64),
\t\tPort:            8443,''',
    "test immutable inputs",
)
replace_once(
    test,
    '''\t\tif f.Path == ".devcontainer/devcontainer.json" && !strings.Contains(f.Content, "v26.3.27") {
\t\t\tt.Fatalf("version pin missing from devcontainer: %s", f.Content)
\t\t}''',
    '''\t\tif f.Path == ".devcontainer/devcontainer.json" {
\t\t\tfor _, required := range []string{"v26.3.27", "debian:bookworm-slim@sha256:", strings.Repeat("b", 64), strings.Repeat("c", 64)} {
\t\t\t\tif !strings.Contains(f.Content, required) { t.Fatalf("immutable input %q missing from devcontainer: %s", required, f.Content) }
\t\t\t}
\t\t}
\t\tif f.Path == ".devcontainer/Dockerfile" && (!strings.Contains(f.Content, "sha256sum -c -") || !strings.Contains(f.Content, "FROM ${BASE_IMAGE}")) {
\t\t\tt.Fatalf("Dockerfile does not verify immutable supply-chain inputs: %s", f.Content)
\t\t}''',
    "test verification",
)
replace_once(
    test,
    '''\tbase := VLESSDevcontainerSpec{UUID: "123e4567-e89b-42d3-a456-426614174000", XrayVersion: "v26.3.27"}''',
    '''\tbase := VLESSDevcontainerSpec{UUID: "123e4567-e89b-42d3-a456-426614174000", XrayVersion: "v26.3.27", BaseImage: "debian:bookworm-slim@sha256:" + strings.Repeat("a", 64), XraySHA256AMD64: strings.Repeat("b", 64), XraySHA256ARM64: strings.Repeat("c", 64)}''',
    "invalid test base",
)
replace_once(
    test,
    '''\tbad = base
\tbad.Path = "relative"''',
    '''\tbad = base
\tbad.BaseImage = "debian:bookworm-slim"
\tif _, err := GenerateVLESSDevcontainer(bad); err == nil {
\t\tt.Fatal("mutable base image accepted")
\t}
\tbad = base
\tbad.XraySHA256AMD64 = "bad"
\tif _, err := GenerateVLESSDevcontainer(bad); err == nil {
\t\tt.Fatal("invalid Xray checksum accepted")
\t}
\tbad = base
\tbad.Path = "relative"''',
    "negative supply-chain tests",
)

ops = "src/packages/control-ui/src/pages/Operations.tsx"
replace_once(
    ops,
    '''  const [devXrayVersion, setDevXrayVersion] = useState('v26.3.27');
  const [devPort, setDevPort] = useState(443);''',
    '''  const [devXrayVersion, setDevXrayVersion] = useState('v26.3.27');
  const [devBaseImage, setDevBaseImage] = useState('');
  const [devXraySHA256AMD64, setDevXraySHA256AMD64] = useState('');
  const [devXraySHA256ARM64, setDevXraySHA256ARM64] = useState('');
  const [devPort, setDevPort] = useState(443);''',
    "Operations immutable state",
)
replace_once(
    ops,
    '''body:JSON.stringify({uuid:devUUID.trim(),xray_version:devXrayVersion.trim(),port:devPort,path:devPath.trim(),mode:devMode})''',
    '''body:JSON.stringify({uuid:devUUID.trim(),xray_version:devXrayVersion.trim(),base_image:devBaseImage.trim(),xray_sha256_amd64:devXraySHA256AMD64.trim(),xray_sha256_arm64:devXraySHA256ARM64.trim(),port:devPort,path:devPath.trim(),mode:devMode})''',
    "Operations request mapping",
)
replace_once(
    ops,
    '''        <p className="m-0 text-sm text-text-secondary">Generate a reviewable Codespaces/devcontainer bundle with a pinned Xray release and first-class XHTTP settings. Generation is read-only; nothing is deployed automatically.</p>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
          <Field label="Client UUID"><input value={devUUID} onChange={(e)=>setDevUUID(e.target.value)} className="field-input mono" /></Field>
          <Field label="Xray version"><input value={devXrayVersion} onChange={(e)=>setDevXrayVersion(e.target.value)} className="field-input mono" /></Field>
          <Field label="Port"><input type="number" min={1} max={65535} value={devPort} onChange={(e)=>setDevPort(Number(e.target.value)||443)} className="field-input" /></Field>''',
    '''        <p className="m-0 text-sm text-text-secondary">Generate a reviewable Codespaces/devcontainer bundle with immutable supply-chain inputs and first-class XHTTP settings. Generation is read-only; nothing is deployed automatically.</p>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          <Field label="Client UUID"><input value={devUUID} onChange={(e)=>setDevUUID(e.target.value)} className="field-input mono" /></Field>
          <Field label="Xray version"><input value={devXrayVersion} onChange={(e)=>setDevXrayVersion(e.target.value)} className="field-input mono" /></Field>
          <Field label="Debian base image digest"><input value={devBaseImage} onChange={(e)=>setDevBaseImage(e.target.value)} placeholder="debian:bookworm-slim@sha256:<64-hex>" className="field-input mono" /></Field>
          <Field label="Xray SHA-256 (amd64)"><input value={devXraySHA256AMD64} onChange={(e)=>setDevXraySHA256AMD64(e.target.value)} placeholder="64 hex characters" className="field-input mono" /></Field>
          <Field label="Xray SHA-256 (arm64)"><input value={devXraySHA256ARM64} onChange={(e)=>setDevXraySHA256ARM64(e.target.value)} placeholder="64 hex characters" className="field-input mono" /></Field>
          <Field label="Port"><input type="number" min={1} max={65535} value={devPort} onChange={(e)=>setDevPort(Number(e.target.value)||443)} className="field-input" /></Field>''',
    "Operations immutable fields",
)

print("F-011 devcontainer supply-chain remediation applied")
