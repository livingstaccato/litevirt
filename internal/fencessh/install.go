package fencessh

import (
	"regexp"
	"strings"
)

// DropInPath is the sshd drop-in `lv host init`, `lv host add` and `lv host
// install-fence-ssh` write. The daemon never writes it: sshd's configuration
// is changed only by an operator's command.
const DropInPath = "/etc/ssh/sshd_config.d/60-litevirt-fence.conf"

// InstallScript defines lv_fence_ssh_install, a bash function that makes this
// host's sshd also accept the keys in /etc/litevirt/ssh/authorized_keys for
// root, through an AuthorizedKeysCommand that cats the file:
//
//	Match User root
//	    AuthorizedKeysCommand /usr/bin/cat /etc/litevirt/ssh/authorized_keys
//	    AuthorizedKeysCommandUser nobody
//
// sshd reads an AuthorizedKeysCommand's keys IN ADDITION to the files of
// AuthorizedKeysFile, so the drop-in never sets AuthorizedKeysFile: every file
// sshd reads for root, from every address, under every Match rule of the
// operator's, is still read, and a host added later is accepted from like any
// other address. What it would override is an AuthorizedKeysCommand of the
// operator's own (sshd takes the first value it obtains, and the drop-in is
// Included first), so where the configuration sets one anywhere, nothing is
// written and the operator is told to add the file's keys to theirs.
//
//   - It checks, with `sshd -T` for a connection from each peer address in
//     FENCE_SSH_PEERS (and FENCE_SSH_SELF), that root's AuthorizedKeysFile is
//     what it was before the drop-in.
//   - It never overrides PermitRootLogin no: it says so, and the daemon then
//     reports the host as not accepting the managed fence key.
//   - It validates with `sshd -t` and, on a refusal, puts the previous
//     drop-in back (or none) and says why: provisioning never breaks sshd.
//   - It reloads sshd (nothing to reload under ssh.socket activation, where
//     each connection reads the configuration) and says so loudly when it
//     cannot: the daemon publishes the host as accepting only once its own
//     login over the managed key works against the running sshd.
//   - FENCE_SSH_REMOVE=1 removes the drop-in instead.
//
// It always returns 0 and reports on stdout. FENCE_SSH_SSHD,
// FENCE_SSH_SSHD_CONFIG, FENCE_SSH_DROPIN_DIR, FENCE_SSH_DIR,
// FENCE_SSH_RELOAD, FENCE_SSH_CAT and FENCE_SSH_AKC_USER override sshd's
// binary, its config, the drop-in directory, the rendered files' directory,
// the reload command, the cat binary and the command's user (tests).
const InstallScript = `
lv_fence_ssh_reload() {
    if [ -n "${FENCE_SSH_RELOAD:-}" ]; then sh -c "$FENCE_SSH_RELOAD"; return $?; fi
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then return 0; fi
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
}
lv_fence_ssh_install() {
    local cfg="${FENCE_SSH_SSHD_CONFIG:-/etc/ssh/sshd_config}"
    local ddir="${FENCE_SSH_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
    local dir="${FENCE_SSH_DIR:-/etc/litevirt/ssh}"
    local sshd="${FENCE_SSH_SSHD:-}"
    local akcuser="${FENCE_SSH_AKC_USER:-nobody}"
    local catbin="${FENCE_SSH_CAT:-}"
    local dropin="$ddir/60-litevirt-fence.conf"
    local ak="$dir/authorized_keys"
    local c
    if [ -z "$sshd" ]; then sshd="$(command -v sshd || true)"; fi
    if [ -z "$sshd" ]; then sshd=/usr/sbin/sshd; fi
    if [ -z "$catbin" ]; then
        for c in /usr/bin/cat /bin/cat; do if [ -x "$c" ]; then catbin="$c"; break; fi; done
    fi
    install -d -m 0755 "$dir"
    if [ ! -x "$sshd" ]; then
        echo "fence ssh: no sshd at $sshd; nothing installed"
        return 0
    fi
    if [ "${FENCE_SSH_REMOVE:-}" = 1 ]; then
        rm -f "$dropin"
        lv_fence_ssh_reload || echo "fence ssh: WARNING: sshd could not be reloaded; it reads the change once it is"
        echo "fence ssh: removed $dropin"
        return 0
    fi
    if ! grep -Eqi "^[[:space:]]*Include[[:space:]]+.*$ddir" "$cfg"; then
        echo "fence ssh: $cfg does not Include $ddir/*.conf, so no drop-in was written. Have sshd also read"
        echo "fence ssh: $ak for root (lv doctor fence shows whether it does)"
        return 0
    fi
    local f own=""
    for f in "$cfg" "$ddir"/*.conf; do
        [ -f "$f" ] || continue
        [ "$f" = "$dropin" ] && continue
        own="$(grep -iE '^[[:space:]]*AuthorizedKeysCommand([[:space:]]|$)' "$f" | head -1)"
        if [ -n "$own" ]; then own="$f: $own"; break; fi
    done
    if [ -n "$own" ]; then
        echo "fence ssh: sshd already has an AuthorizedKeysCommand ($own), which a drop-in would override, so"
        echo "fence ssh: none was written. Have it also print the keys in $ak for root"
        return 0
    fi
    local prev=""
    if [ -f "$dropin" ]; then
        prev="$(mktemp "$ddir/.litevirt-fence.prev.XXXXXX")"
        cp -p "$dropin" "$prev"
        rm -f "$dropin"
    fi
    local addrs="${FENCE_SSH_PEERS:-} ${FENCE_SSH_SELF:-}"
    if [ -z "$(echo $addrs)" ]; then addrs=127.0.0.1; fi
    local a out before="" seen=" "
    for a in $addrs; do
        case "$seen" in *" $a "*) continue ;; esac
        seen="$seen$a "
        if ! out="$("$sshd" -T -f "$cfg" -C "user=root,host=,addr=$a" 2>&1)"; then
            if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
            echo "fence ssh: sshd -T failed ($out); nothing changed"
            return 0
        fi
        before="$before$a $(printf '%s
' "$out" | awk '$1=="authorizedkeysfile"' | head -1)
"
        if [ "$(printf '%s
' "$out" | awk '$1=="permitrootlogin" { print $2; exit }')" = no ]; then
            echo "fence ssh: PermitRootLogin is no for root from $a; litevirt does not override it, and this host"
            echo "fence ssh: reports that it does not accept the managed fence key"
        fi
    done
    local tmp="$dropin.tmp.$$"
    {
        echo "# Written by litevirt (lv host init, lv host add, lv host install-fence-ssh): sshd also accepts the"
        echo "# keys in $ak for root. It sets no AuthorizedKeysFile, so every file sshd reads stays read."
        echo "Match User root"
        echo "    AuthorizedKeysCommand $catbin $ak"
        echo "    AuthorizedKeysCommandUser $akcuser"
        echo "Match all"
    } > "$tmp"
    chmod 0644 "$tmp"
    mv "$tmp" "$dropin"
    local after=""
    if out="$("$sshd" -t -f "$cfg" 2>&1)"; then
        for a in $(echo "$before" | awk '{print $1}'); do
            after="$after$a $("$sshd" -T -f "$cfg" -C "user=root,host=,addr=$a" 2>/dev/null | awk '$1=="authorizedkeysfile"' | head -1)
"
        done
    fi
    if [ "$after" != "$before" ]; then
        rm -f "$dropin"
        if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
        if [ -z "$after" ]; then
            echo "fence ssh: sshd -t refused the drop-in ($out); it was rolled back and sshd is unchanged"
        else
            echo "fence ssh: the drop-in changed the files sshd reads for root; it was rolled back and sshd is unchanged"
        fi
        return 0
    fi
    if [ -n "$prev" ]; then rm -f "$prev"; fi
    if ! lv_fence_ssh_reload; then
        echo "fence ssh: WARNING: sshd could not be reloaded, so it does not read $dropin yet. This host reports that it"
        echo "fence ssh: does not accept the managed fence key until sshd does (reload or restart it)"
    fi
    echo "fence ssh: $dropin installed"
    return 0
}
`

// RevocationHoldPrefix starts the reason a replaced certificate's revocation
// is held as owed while its host's fence ssh row is still signed by it.
const RevocationHoldPrefix = "fence ssh row not yet re-signed: "

var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// PeerAddresses is every IPv4 literal in s (a YAML join_peers list, a host
// list), deduplicated, space-separated: FENCE_SSH_PEERS.
func PeerAddresses(s string) string {
	seen := map[string]bool{}
	var out []string
	for _, a := range ipv4Re.FindAllString(s, -1) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}
