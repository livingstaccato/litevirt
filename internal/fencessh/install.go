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
//   - It reloads a running ssh.service or sshd.service, also when ssh.socket
//     starts it (Ubuntu 22.10 and later, 24.04 LTS: one persistent sshd listener, whose
//     children take its configuration). Only with no service running and a
//     socket unit listening is there nothing to reload: the next connection
//     starts sshd from the new configuration. It says so loudly when it
//     cannot reload: the daemon publishes the host as accepting only once its
//     own login over the managed key works against the running sshd.
//   - FENCE_SSH_REMOVE=1 removes the drop-in instead.
//
// It always returns 0 and reports on stdout, and sets LV_FENCE_SSH_RESULT to
// its outcome: ResultInstalled, ResultRemoved, ResultUnreloaded or
// ResultRefused. FENCE_SSH_SSHD,
// FENCE_SSH_SSHD_CONFIG, FENCE_SSH_DROPIN_DIR, FENCE_SSH_DIR,
// FENCE_SSH_RELOAD, FENCE_SSH_CAT and FENCE_SSH_AKC_USER override sshd's
// binary, its config, the drop-in directory, the rendered files' directory,
// the reload command, the cat binary and the command's user (tests).
const InstallScript = `
# lv_fence_ssh_reload has the running sshd read its configuration again, and
# returns non-zero, saying why, when it cannot tell that it will.
#   - A running ssh.service or sshd.service is reloaded, whether or not a
#     socket unit starts it: under ssh.socket with Accept=no (Ubuntu 22.10
#     and later, 24.04 LTS) the service is one persistent listener whose children take its
#     configuration, so a reload is the only way it reads the drop-in.
#   - With no service running but ssh.socket or sshd.socket listening, there
#     is nothing to reload: the next connection starts sshd (or, with
#     Accept=yes, an sshd per connection) from the configuration on disk.
#   - With neither, nothing here knows how sshd is run: it is not reloaded.
#   - First, sshd -t must pass on the configuration (the caller's $sshd and
#     $cfg): a reload of one sshd refuses (sshd.service's ExecReload is a bare
#     SIGHUP on some distributions) stops the listener. Both callers, install
#     and FENCE_SSH_REMOVE, go through it.
# Either way the daemon publishes the host as accepting only once its own
# login over the managed key works against the running sshd.
lv_fence_ssh_reload() {
    if [ -n "${FENCE_SSH_RELOAD:-}" ]; then sh -c "$FENCE_SSH_RELOAD"; return $?; fi
    local u st out
    local sd="${sshd:-${FENCE_SSH_SSHD:-/usr/sbin/sshd}}" sc="${cfg:-${FENCE_SSH_SSHD_CONFIG:-/etc/ssh/sshd_config}}"
    if ! out="$("$sd" -t -f "$sc" 2>&1)"; then
        echo "fence ssh: sshd -t -f $sc fails, so sshd was not reloaded (a reload would stop it): $out"
        return 1
    fi
    for u in ssh.service sshd.service; do
        st="$(systemctl is-active "$u" 2>/dev/null)"
        case "$st" in
        active|reloading|activating)
            if out="$(systemctl reload "$u" 2>&1)"; then return 0; fi
            echo "fence ssh: systemctl reload $u failed: $out"
            return 1 ;;
        esac
    done
    for u in ssh.socket sshd.socket; do
        if [ "$(systemctl is-active "$u" 2>/dev/null)" = active ]; then
            echo "fence ssh: $u is listening and no sshd service runs yet; the next connection starts sshd with this configuration"
            return 0
        fi
    done
    echo "fence ssh: neither ssh.service nor sshd.service runs, and neither ssh.socket nor sshd.socket listens, so litevirt"
    echo "fence ssh: cannot reload sshd"
    return 1
}
# lv_fence_ssh_akc_line prints the first line of file $1 whose keyword,
# read the way sshd reads one (leading blanks, carriage returns and "="
# skipped, a carriage return a blank, quotes removed, any case), is
# AuthorizedKeysCommand. Conservative: a line that is only close to one still
# counts, since a false match only means no drop-in.
lv_fence_ssh_akc_line() {
    awk '{
        l = $0
        gsub("[\"\047]", "", l)
        sub("^[ \t\r=]+", "", l)
        if (l ~ /^#/) next
        split(l, w, "[ \t\r=]+")
        if (tolower(w[1]) == "authorizedkeyscommand") { print $0; exit }
    }' "$1"
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
    LV_FENCE_SSH_RESULT=refused
    if [ -z "$sshd" ]; then sshd="$(command -v sshd || true)"; fi
    if [ -z "$sshd" ]; then sshd=/usr/sbin/sshd; fi
    if [ -z "$catbin" ]; then
        for c in /usr/bin/cat /bin/cat "$(command -v cat 2>/dev/null || true)"; do
            if [ -n "$c" ] && [ -x "$c" ]; then catbin="$c"; break; fi
        done
    fi
    install -d -m 0755 "$dir"
    if [ ! -x "$sshd" ]; then
        echo "fence ssh: no sshd at $sshd; nothing installed"
        return 0
    fi
    if [ "${FENCE_SSH_REMOVE:-}" = 1 ]; then
        rm -f "$dropin"
        if lv_fence_ssh_reload; then
            LV_FENCE_SSH_RESULT=removed
        else
            LV_FENCE_SSH_RESULT=unreloaded
            echo "fence ssh: WARNING: sshd could not be reloaded; it reads the change once it is"
        fi
        echo "fence ssh: removed $dropin"
        return 0
    fi
    if ! grep -Eqi "^[[:space:]]*Include[[:space:]]+.*$ddir" "$cfg"; then
        echo "fence ssh: $cfg does not Include $ddir/*.conf, so no drop-in was written. Have sshd also read"
        echo "fence ssh: $ak for root (lv doctor fence shows whether it does)"
        return 0
    fi
    case "$catbin" in /*) ;; *) catbin="" ;; esac
    if [ -z "$catbin" ] || [ ! -x "$catbin" ]; then
        echo "fence ssh: no cat binary at an absolute path (sshd runs an AuthorizedKeysCommand by its absolute path),"
        echo "fence ssh: so no drop-in was written. Have sshd also read $ak for root"
        return 0
    fi
    local prev=""
    if [ -f "$dropin" ]; then
        prev="$(mktemp "$ddir/.litevirt-fence.prev.XXXXXX")"
        cp -p "$dropin" "$prev"
        rm -f "$dropin"
    fi
    # The operator's own AuthorizedKeysCommand is never replaced: sshd takes
    # the first one it reads, and the drop-in is Included first. Every file
    # sshd reads (sshd -ddd names each; a scan that fails or does not name the
    # main config is no scan, and nothing is installed), every line tokenised
    # the way sshd reads it (leading blanks and "=", quotes), and root's
    # effective value for every evaluated address.
    local f own="" scan files
    if ! scan="$("$sshd" -ddd -T -f "$cfg" -C "user=root,host=,addr=127.0.0.1" 2>&1)"; then
        if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
        echo "fence ssh: sshd -ddd -T failed, so the files sshd reads cannot be checked for an AuthorizedKeysCommand;"
        echo "fence ssh: no drop-in was written. Have sshd also read $ak for root. sshd said:"
        printf '%s\n' "$scan" | tr -d '\r' | grep -v '^debug' | tail -n 3 | sed 's/^/fence ssh:   /'
        return 0
    fi
    files="$(printf '%s\n' "$scan" | tr -d '\r' | sed -n 's/.*load_server_config: filename //p')"
    if ! printf '%s\n' "$files" | grep -Fxq -- "$cfg"; then
        if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
        echo "fence ssh: could not list the files sshd reads (sshd -ddd -T named no $cfg), so they cannot be checked"
        echo "fence ssh: for an AuthorizedKeysCommand; no drop-in was written. Have sshd also read $ak for root"
        return 0
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ "$f" = "$dropin" ] && continue
        if [ ! -r "$f" ]; then own="$f: unreadable, so it cannot be checked"; break; fi
        own="$(lv_fence_ssh_akc_line "$f")"
        if [ -n "$own" ]; then own="$f: $own"; break; fi
    done <<LVFILES
$files
LVFILES
    local addrs="${FENCE_SSH_PEERS:-} ${FENCE_SSH_SELF:-}"
    if [ -z "$(echo $addrs)" ]; then addrs=127.0.0.1; fi
    local a out akc before="" seen=" "
    for a in $addrs; do
        case "$seen" in *" $a "*) continue ;; esac
        seen="$seen$a "
        if ! out="$("$sshd" -T -f "$cfg" -C "user=root,host=,addr=$a" 2>&1)"; then
            if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
            echo "fence ssh: sshd -T failed ($out); nothing changed"
            return 0
        fi
        akc="$(printf '%s\n' "$out" | awk '$1=="authorizedkeyscommand" { $1=""; sub(/^ +/, ""); print; exit }')"
        if [ -z "$own" ] && [ -n "$akc" ] && [ "$akc" != none ]; then own="root's effective AuthorizedKeysCommand from $a: $akc"; fi
        before="$before$a $(printf '%s\n' "$out" | awk '$1=="authorizedkeysfile"' | head -1)
"
        if [ "$(printf '%s
' "$out" | awk '$1=="permitrootlogin" { print $2; exit }')" = no ]; then
            echo "fence ssh: PermitRootLogin is no for root from $a; litevirt does not override it, and this host"
            echo "fence ssh: reports that it does not accept the managed fence key"
        fi
    done
    if [ -n "$own" ]; then
        if [ -n "$prev" ]; then mv "$prev" "$dropin"; fi
        echo "fence ssh: sshd already has an AuthorizedKeysCommand ($own), which a drop-in would replace for root, so"
        echo "fence ssh: none was written. Have it also print the keys in $ak for root"
        return 0
    fi
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
            out="$("$sshd" -T -f "$cfg" -C "user=root,host=,addr=$a" 2>/dev/null)"
            akc="$(printf '%s\n' "$out" | awk '$1=="authorizedkeyscommand" { $1=""; sub(/^ +/, ""); print; exit }')"
            if [ "$akc" != "$catbin $ak" ]; then after="$after$a authorizedkeyscommand $akc
"; continue; fi
            after="$after$a $(printf '%s\n' "$out" | awk '$1=="authorizedkeysfile"' | head -1)
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
    LV_FENCE_SSH_RESULT=installed
    if ! lv_fence_ssh_reload; then
        LV_FENCE_SSH_RESULT=unreloaded
        echo "fence ssh: WARNING: sshd could not be reloaded, so it does not read $dropin yet. This host reports that it"
        echo "fence ssh: does not accept the managed fence key until sshd does (reload or restart it)"
    fi
    echo "fence ssh: $dropin installed"
    return 0
}
`

// The outcomes InstallScript sets LV_FENCE_SSH_RESULT to.
const (
	// ResultInstalled: the drop-in is in place and sshd was reloaded (or a
	// listening socket unit starts it from the new configuration).
	ResultInstalled = "installed"
	// ResultRemoved: the drop-in is gone and sshd was reloaded.
	ResultRemoved = "removed"
	// ResultUnreloaded: the drop-in was written or removed, but the running
	// sshd was not reloaded, so it does not read the change yet.
	ResultUnreloaded = "unreloaded"
	// ResultRefused: nothing was changed (every refusal the script says why).
	ResultRefused = "refused"
)

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
