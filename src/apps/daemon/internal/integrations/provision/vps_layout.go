package provision

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func generateProvisionSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate provisioning secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func buildManagedLayoutScript(root, composeCommand, composeContent, dockerfileContent, torrcContent string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" || strings.ContainsAny(root, "\x00\r\n") {
		return "", errors.New("managed layout root is invalid")
	}
	if composeCommand != "docker compose" && composeCommand != "docker-compose" {
		return "", fmt.Errorf("unsupported compose command %q", composeCommand)
	}
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	q := shellSingleQuote
	script := fmt.Sprintf(`set -euo pipefail
root=%s
marker="$root/.luminet-managed"
generations="$root/.luminet-generations"

# Ownership must be established before rollback is armed. A legacy LumiNet
# layout can be adopted only when every top-level entry is known and the old
# compose file carries LumiNet's canonical container identity.
if [ -L "$root" ]; then echo "unmanaged layout: root is a symlink" >&2; exit 42; fi
if [ -d "$root" ] && [ ! -e "$marker" ]; then
  unknown="$(find "$root" -mindepth 1 -maxdepth 1 \
    ! -name docker-compose.yml ! -name tor ! -name db ! -name cert ! -name pgdata -print -quit)"
  if [ -n "$unknown" ]; then echo "unmanaged layout: unknown entry $unknown" >&2; exit 42; fi
  for state in db cert pgdata; do
    if [ -e "$root/$state" ] && { [ -L "$root/$state" ] || [ ! -d "$root/$state" ]; }; then
      echo "unmanaged layout: state path $state is not a real directory" >&2; exit 42
    fi
  done
  if [ -e "$root/docker-compose.yml" ]; then
    if [ -L "$root/docker-compose.yml" ] || [ ! -f "$root/docker-compose.yml" ] || ! grep -q 'container_name: 3xui_app' "$root/docker-compose.yml"; then
      echo "unmanaged layout: legacy compose ownership cannot be proven" >&2; exit 42
    fi
  fi
  if [ -e "$root/tor" ] && { [ -L "$root/tor" ] || [ ! -d "$root/tor" ]; }; then
    echo "unmanaged layout: legacy tor path is not a real directory" >&2; exit 42
  fi
fi
if [ -L "$marker" ]; then echo "unmanaged layout: ownership marker is a symlink" >&2; exit 42; fi
if [ -e "$generations" ] && { [ -L "$generations" ] || [ ! -d "$generations" ]; }; then
  echo "unmanaged layout: generation path is not a real directory" >&2; exit 42
fi

mkdir -p "$root" "$generations" "$root/db" "$root/cert" "$root/pgdata"
chmod 700 "$root" "$generations"
umask 077
stage="$(mktemp -d "$generations/.stage.XXXXXX")"
mkdir -p "$stage/tor"
printf '%%s' %s | base64 -d > "$stage/docker-compose.yml"
printf '%%s' %s | base64 -d > "$stage/tor/Dockerfile"
printf '%%s' %s | base64 -d > "$stage/tor/torrc"
chmod 600 "$stage/docker-compose.yml"
chmod 644 "$stage/tor/Dockerfile" "$stage/tor/torrc"

compose_cmd=%s
previous="$(readlink "$root/current" 2>/dev/null || true)"
had_marker=0
[ -f "$marker" ] && had_marker=1
final=""
published=0
rollback() {
  status=$?
  [ "$status" -eq 0 ] && status=1
  set +e
  if [ "$published" = "1" ]; then
    if [ -n "$previous" ]; then
      ln -s "$previous" "$root/current.rollback"
      mv -Tf "$root/current.rollback" "$root/current"
    else
      rm -f "$root/current"
    fi
    if [ -n "$previous" ] && [ -f "$previous/docker-compose.yml" ]; then
      $compose_cmd -f "$previous/docker-compose.yml" up -d --build >/dev/null 2>&1
    elif [ -f "$root/docker-compose.yml" ]; then
      (cd "$root" && $compose_cmd up -d --build >/dev/null 2>&1)
    fi
  fi
  [ "$had_marker" = "0" ] && rm -f "$marker"
  [ -n "$final" ] && rm -rf "$final"
  [ -n "$stage" ] && rm -rf "$stage"
  exit "$status"
}
trap rollback ERR INT TERM

# Validate the staged generation before any authoritative pointer changes.
$compose_cmd -f "$stage/docker-compose.yml" config >/dev/null
final="$generations/gen-$(date +%%s)-$$"
mv "$stage" "$final"
stage=""
printf 'version=1\n' > "$root/.luminet-managed.next"
chmod 600 "$root/.luminet-managed.next"
mv -f "$root/.luminet-managed.next" "$marker"
ln -s "$final" "$root/current.next"
mv -Tf "$root/current.next" "$root/current"
published=1
$compose_cmd -f "$root/current/docker-compose.yml" up -d --build
trap - ERR INT TERM
`, q(root), q(encode(composeContent)), q(encode(dockerfileContent)), q(encode(torrcContent)), q(composeCommand))
	return script, nil
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
