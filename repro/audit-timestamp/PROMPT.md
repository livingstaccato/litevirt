Paste the block below to an agent on the Linux machine.

```text
Verify a Go fix on this machine. Do not edit code, commit, push, or open
pull requests — this is a read-and-run task.

1. Requirements: git, make, and Go 1.26 or newer (`go version`; with
   GOTOOLCHAIN=auto an older Go downloads 1.26 itself). Network access to
   github.com is needed.

2. Get the branch:
     git clone -b repro/audit-timestamp-order https://github.com/livingstaccato/litevirt.git litevirt-audit-repro
     cd litevirt-audit-repro

3. Read repro/audit-timestamp/README.md first. It says what is being proved,
   what each step does, and what counts as a pass.

4. Run the script from the repository root (takes several minutes):
     bash repro/audit-timestamp/run.sh 2>&1 | tee repro-output.txt

5. Report back:
   - the "context" block (branch, base, fix, go, os, out)
   - every line starting with "RESULT"
   - the script's exit code (0 = no RESULT FAIL)
   - for any RESULT FAIL or INFO, the matching log file from the "out"
     directory the script printed (tail is enough unless the failure is
     unclear)
   - specifically: does TestSIGPIPEDoesNotKillTheProcess pass or fail here,
     and how many breaks did steps 1 and 3 see on this host's clock

Do not try to fix a failure. Report it with the log.
```
