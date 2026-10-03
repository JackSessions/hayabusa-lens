"""Download a small set of REAL Windows event logs for trying the tool. Nothing is bundled: the files are fetched, on request,
from the public Hayabusa sample collection (https://github.com/Yamato-Security/hayabusa-sample-evtx), which gathers logs from
DeepBlueCLI, EVTX-ATTACK-SAMPLES (@SBousseaden), EVTX-to-MITRE-Attack and Yamato Security. Credit and licences belong to those projects."""
from __future__ import annotations

import os
import urllib.parse
import urllib.request

REPO = "https://raw.githubusercontent.com/Yamato-Security/hayabusa-sample-evtx/main/"
HOME = os.path.join(os.path.expanduser("~"), ".hayabusa-lens", "sample-logs")

# (path inside the sample repo, size in bytes). Chosen to cover several ATT&CK tactics in a few MB.
FILES: list[tuple[str, int]] = [
    ('EVTX-ATTACK-SAMPLES/Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/AutomatedTestingTools/WinDefender_Events_1117_1116_AtomicRedTeam.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Credential Access/babyshark_mimikatz_powershell.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_11_7_1_uacbypass_windirectory_mocking.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Lateral Movement/LM_impacket_docmexec_mmc_sysmon_01.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Command and Control/DE_RDP_Tunnel_5156.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Defense Evasion/sysmon_13_rdp_settings_tampering.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_roguepotato_sysmon_17_18.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Execution/sysmon_exec_from_vss_persistence.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_11_lsass_memdump.evtx', 69632),
    ('EVTX-ATTACK-SAMPLES/Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx', 69632),
]


class SamplesError(Exception):
    pass


def total_mb() -> float:
    return sum(s for _, s in FILES) / 1048576


def download(dest: str | None = None, progress=None, base: str = REPO, files=None, opener=urllib.request.urlopen) -> str:
    """Fetch the files into `dest` (default ~/.hayabusa-lens/sample-logs). progress(done_files, total_files, name). Returns the folder."""
    files = FILES if files is None else files
    dest = dest or HOME
    os.makedirs(dest, exist_ok=True)
    say = progress or (lambda *a: None)
    for n, (path, _) in enumerate(files, 1):
        name = os.path.basename(path)
        target = os.path.join(dest, name)
        say(n - 1, len(files), name)
        if os.path.exists(target) and os.path.getsize(target) > 0:
            continue
        url = base + urllib.parse.quote(path)
        try:
            with opener(urllib.request.Request(url, headers={"User-Agent": "hayabusa-lens"}), timeout=60) as r, open(target + ".part", "wb") as out:
                out.write(r.read())
            os.replace(target + ".part", target)
        except Exception as e:
            if os.path.exists(target + ".part"):
                os.unlink(target + ".part")
            raise SamplesError(f"Could not download {name} ({e}). Check your internet connection.") from e
    say(len(files), len(files), "done")
    with open(os.path.join(dest, "README.txt"), "w", encoding="utf-8") as f:
        f.write("Sample logs downloaded by Hayabusa Lens from https://github.com/Yamato-Security/hayabusa-sample-evtx\n"
                "They come from DeepBlueCLI, EVTX-ATTACK-SAMPLES, EVTX-to-MITRE-Attack and Yamato Security. Credit and licences belong to those projects.\n"
                "Your antivirus may flag them because of attack keywords such as 'mimikatz'. They contain no executable code.\n")
    return dest
