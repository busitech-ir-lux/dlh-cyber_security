# Rule Validation Report — IR-2026-0414-01

## Method
Tested supplied Sigma detection selections against the supplied **normalized** JSONL schema (`event_id`, `image`, `parent_image`, `dst_ip`, `dst_hostname`, `initiated`) with `match_sigma_samples.py`. The matcher supports only the modifiers/conditions used by these rules; it is not a full SIEM/Sigma backend. YAML parsed with PyYAML. Actual uploaded sample sizes are 17 and 21 (the assignment's much larger event counts are illustrative, not the files delivered here).

| Rule | Sample | Events | Matches | Match rate |
|---|---|---:|---:|---:|
| PowerShell → developer utility | Incident | 17 | 2 | 11.765% |
| PowerShell → developer utility | Clean | 21 | 0 | 0.000% |
| MSBuild public outbound | Incident | 17 | 2 | 11.765% |
| MSBuild public outbound (tuned) | Clean | 21 | 0 | 0.000% |

**Positive detections:** EID 1 at 2026-04-14 02:46:58Z (WST-WS-031 / PID 8104) and 03:27:13Z (WST-WS-017 / PID 5108). Network EID 3 at 02:47:02Z and 03:27:15Z to 185.220.101.47 and 91.234.99.107.

## Tuning
- **Network rule before NuGet filtering:** 14/21 clean events match (66.667%) because legitimate `MSBuild.exe` connects to `api.nuget.org` at `168.62.42.37`. The 14 hits are all `MSBuild.exe` EID 3 on baseline host WST-WS-042, and associated with `api.nuget.org`.
- **After tuning:** Exclude RFC1918 IPs using proper CIDR ranges, loopback, and destination hostnames ending in `.nuget.org` or `.nugetstatic.com`; also describe the observed IP + hostname pair. Clean matches reduce to 0/21; incident matches remain 2/17.
- The process rule required no tuning on the provided sample.

## Assessment
Both rules fire on the known incident examples and yield a measured **0.000% clean-sample event match rate**, below the <0.1% task target on this small sample only. Because only **21 benign events** were supplied, this is not reliable evidence that production FPR will be below 0.1%. It is also an event match rate, not a statistically validated false-positive rate without comprehensive benign labels. Validate on a full representative baseline before deployment, especially for builds using NuGet alternative hosts.

## Tool/quality boundaries
`yamllint` and `sigma-cli` binaries were not available in the authoring environment. YAML was parsed successfully with PyYAML and evaluated by the included simplified matcher. A production backend conversion, Sigma schema check, SIEM field mapping, and end-to-end detection exercise are still required.

## Verification commands
```bash
python3 -m pip install pyyaml
./validate_rules.sh /path/to/5x03
# If installed:
yamllint sigma_*.yml
sigma check sigma_powershell_msbuild_lolbin.yml
sigma check sigma_msbuild_network_connection.yml
```
