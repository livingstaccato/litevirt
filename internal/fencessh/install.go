package fencessh

import (
	"regexp"
	"strings"
)

// DropInPath is the sshd drop-in `lv host init` and `lv host add` write. The daemon never writes it: sshd's configuration
// is changed only by an operator's command.
const DropInPath = "/etc/ssh/sshd_config.d/60-litevirt-fence.conf"

// InstallScript defines lv_fence_ssh_install, a bash function that makes this
// host's sshd read /etc/litevirt/ssh/authorized_keys for root, keeping every
// file sshd already reads for root:
//
//   - It evaluates root's effective AuthorizedKeysFile with `sshd -T`, its own
//     drop-in set aside (so a re-run never adds the file twice), for a
//     connection from each peer address in FENCE_SSH_PEERS (and FENCE_SSH_SELF),
//     because a Match Address block can give root another list for one peer.
//     When every address gets the same list it writes one `Match User root`
//     block; otherwise one `Match User root Address <peer>` block per peer.
//     That freezes the list for root as it is now: a later edit of the global
//     AuthorizedKeysFile does not reach root until this is run again.
//   - It never overrides PermitRootLogin no: it says so, and the daemon then
//     reports the host as not accepting the managed fence key.
//   - It validates with `sshd -t` and, on a refusal, puts the previous
//     drop-in back (or none) and says why: provisioning never breaks sshd.
//   - FENCE_SSH_REMOVE=1 removes the drop-in instead.
//
// It always returns 0 and reports on stdout; whether the host accepts the
// managed key is the daemon's to evaluate and publish. FENCE_SSH_SSHD,
// FENCE_SSH_SSHD_CONFIG, FENCE_SSH_DROPIN_DIR, FENCE_SSH_DIR and
// FENCE_SSH_RELOAD override sshd's binary, its config, the drop-in directory,
// the rendered files' directory and the reload command (tests).
const InstallScript = `
lv_fence_ssh_install() {
    local cfg="${FENCE_SSH_SSHD_CONFIG:-/etc/ssh/sshd_config}"
    local ddir="${FENCE_SSH_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
    local dir="${FENCE_SSH_DIR:-/etc/litevirt/ssh}"
    local sshd="${FENCE_SSH_SSHD:-}"
    local reload="${FENCE_SSH_RELOAD:-systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true}"
    local dropin="$ddir/60-litevirt-fence.conf"
    local ak="$dir/authorized_keys"
    if [ -z "$sshd" ]; then sshd="$(command -v sshd || true)"; fi
    if [ -z "$sshd" ]; then sshd=/usr/sbin/sshd; fi
    install -d -m 0755 "$dir"
    if [ ! -x "$sshd" ]; then
        echo "fence ssh: no sshd at $sshd; nothing installed"
        return 0
    fi
    if [ "${FENCE_SSH_REMOVE:-}" = 1 ]; then
        rm -f "$dropin"
        sh -c "$reload"
        echo "fence ssh: removed $dropin"
        return 0
    fi
    if ! grep -Eqi "^[[:space:]]*Include[[:space:]]+.*$ddir" "$cfg"; then
        echo "fence ssh: $cfg does not Include $ddir/*.conf, so no drop-in was written. Add $ak to root's"
        echo "fence ssh: AuthorizedKeysFile by hand (lv doctor fence shows whether sshd reads it)"
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
    local a out akf prl first="" same=1 lines="" seen=" "
    for a in $addrs; do
        case "$seen" in *" $a "*) continue ;; esac
        seen="$seen$a "
        if ! out="$("$sshd" -T -f "$cfg" -C "user=root,host=,addr=$a" 2>&1)"; then
            if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
            echo "fence ssh: sshd -T failed ($out); nothing changed"
            return 0
        fi
        akf="$(printf '%s\n' "$out" | awk '$1=="authorizedkeysfile" { $1=""; sub(/^ +/, ""); print; exit }')"
        prl="$(printf '%s\n' "$out" | awk '$1=="permitrootlogin" { print $2; exit }')"
        if [ "$akf" = none ]; then akf=""; fi
        akf="$(printf ' %s ' "$akf" | sed "s# $ak # #g" | xargs)"
        if [ "$prl" = no ]; then
            echo "fence ssh: PermitRootLogin is no for root from $a; litevirt does not override it, and this host"
            echo "fence ssh: reports that it does not accept the managed fence key"
        fi
        if [ -z "$first" ]; then first="$akf"; elif [ "$akf" != "$first" ]; then same=0; fi
        lines="$lines$a|$akf
"
    done
    local tmp="$dropin.tmp.$$"
    {
        echo "# Written by litevirt (lv host init, lv host add): sshd also reads"
        echo "# $ak for root, keeping the list it read for root when this was written."
        if [ "$same" = 1 ]; then
            echo "Match User root"
            echo "    AuthorizedKeysFile $first $ak"
        else
            printf '%s' "$lines" | while IFS='|' read -r a akf; do
                [ -n "$a" ] || continue
                echo "Match User root Address $a"
                echo "    AuthorizedKeysFile $akf $ak"
            done
        fi
        echo "Match all"
    } > "$tmp"
    chmod 0644 "$tmp"
    mv "$tmp" "$dropin"
    if ! out="$("$sshd" -t -f "$cfg" 2>&1)"; then
        rm -f "$dropin"
        if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
        echo "fence ssh: sshd -t refused the drop-in ($out); it was rolled back and sshd is unchanged"
        return 0
    fi
    if [ -n "$prev" ]; then rm -f "$prev"; fi
    for a in $addrs; do
        if ! "$sshd" -T -f "$cfg" -C "user=root,host=,addr=$a" 2>/dev/null | awk '$1=="authorizedkeysfile"' | grep -qF " $ak"; then
            echo "fence ssh: an earlier sshd setting still gives root another AuthorizedKeysFile for $a; fix it, then re-run"
        fi
    done
    sh -c "$reload"
    echo "fence ssh: $dropin installed"
    return 0
}
`

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
