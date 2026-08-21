"""Transfer and materialize a verified off-host bundle on the sole `.240` VM.

No SMB/UNC path is assumed.  OpenSSH performs an empty-root preflight, SCP
places one immutable bundle under the exact D-root recovery import directory,
and the bundled Python/tool restore it in place.  No command targets C, a D
parent, or a sibling project path.
"""

from __future__ import annotations

import argparse
import base64
from datetime import UTC, datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
from typing import Callable, Mapping, Sequence
from uuid import uuid4

from quant_hub.config import ensure_no_reparse_components

from .publish_adapters import (
    CommandResult,
    exact_production_root_parent_guard_script,
    subprocess_runner,
)
from .publish_runtime import RuntimePublishConfig
from .recovery_bundle import RecoveryVerification, verify_recovery_bundle
from .failure_domain import attest_failure_domain
from .vm_boundary import (
    PRODUCTION_WRITE_AREAS,
    declared_production_vm_write_set,
)


class ColdRestoreCLIError(RuntimeError):
    pass


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PREPARE_INSPECTION_SCHEMA = "qrh-prepare-empty-inspection/v1"
_PREPARE_APPLY_SCHEMA = "qrh-prepare-empty-application/v1"
_QUALIFICATION_RESET_INSPECTION_SCHEMA = (
    "qrh-prepare-empty-qualification-reset-inspection/v1"
)
_QUALIFICATION_RESET_APPLY_SCHEMA = (
    "qrh-prepare-empty-qualification-reset-application/v1"
)
_LEGACY_V39_DEPLOYMENT_ID = "quant-hub-v39-company-broadcast-20260731-hotfix1"
_LEGACY_V39_PYTHON_PATH_SHA256 = (
    "187c79755d766743dd778487a796b354597c18a676888168fb75f09eba9539b0"
)
_LEGACY_V39_PYTHON_BYTES = 105288
_LEGACY_V39_PYTHON_SHA256 = (
    "f3c05e11e9fc3fc0941fda221b1dfb0aac39d6ef298078054a5d949d620f3d6c"
)
# The sealed V39 package intentionally carries two empty runtime trees.  Its
# file inventory binds every byte, while these four directory records are the
# only byte-free descendants preserved by copytree.  Qualification reset may
# observe them, but no other unmanifested directory is accepted.
_LEGACY_V39_EMPTY_RELEASE_DIRECTORIES = (
    "runtime/inbox",
    "runtime/inbox/research",
    "runtime/replay",
    "runtime/replay/evidence",
)
_TRANSFER_ATTEMPT_SCHEMA = "qrh-cold-restore-transfer-attempt/v1"
_LEGACY_MATERIALIZATION_SERIALIZATION = "legacy_powershell_hashtable_v1"


def _legacy_materialization_event_bytes(event: Mapping[str, object]) -> bytes:
    """Rebuild the one already-published PS 5.1 hashtable byte profile.

    The first qualification restore used an ordinary PowerShell hashtable. On
    the qualification host that fixed implementation emitted the order below.
    This is deliberately not a semantic-JSON fallback: reset accepts only the
    resulting exact bytes/hash, alongside the canonical off-host authority.
    """

    fields = event.get("fields")
    if not isinstance(fields, dict):
        raise ColdRestoreCLIError("qualification materialization fields are invalid")
    legacy = {
        "schema_version": event["schema_version"],
        "authority": event["authority"],
        "event_id": event["event_id"],
        "fields": {
            "import_cleaned": fields["import_cleaned"],
            "empty_root_precondition": fields["empty_root_precondition"],
            "bundle_id": fields["bundle_id"],
            "runtime_tmp_cleaned": fields["runtime_tmp_cleaned"],
            "manifest_sha256": fields["manifest_sha256"],
            "release_id": fields["release_id"],
        },
        "kind": event["kind"],
    }
    return json.dumps(
        legacy,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

# The D-root Python may run only after the complete operational/file closure is
# proven.  It is used solely to prove the existing VM-write audit has the exact
# canonical byte format emitted by write_atomic_new_json; ADS and argv checks
# use the off-script Reflection.Emit Win32 binding below and never depend on D.
_CANONICAL_AUDIT_PROBE = r'''import hashlib as h
import json as j
import os
import sys

root = os.path.abspath(sys.argv[1])
audit = os.path.abspath(sys.argv[2])
if os.path.commonpath([os.path.normcase(root), os.path.normcase(audit)]) != os.path.normcase(root):
    raise RuntimeError("qualification_audit_path_escape")
raw = open(audit, "rb").read()
v = j.loads(raw.decode("utf-8"))
canonical = (j.dumps(v, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
if raw != canonical:
    raise RuntimeError("qualification_candidate_audit_not_canonical")
declared = j.dumps(
    v.get("declared_write_set"), ensure_ascii=False, sort_keys=True,
    separators=(",", ":"), allow_nan=False,
).encode("utf-8")
strings = ("schema_version", "operation", "authority_root", "verdict", "audit_id", "outcome", "audit_record_path")
writes = v.get("observed_writes")
ok = all(type(v.get(n)) is str for n in strings) and type(v.get("declared_write_set")) is dict and type(writes) is list
if ok:
    ok = all(type(n) is str and type(p) is str for n, p in v["declared_write_set"].items())
if ok:
    ok = all(type(w) is dict and all(type(w.get(n)) is str for n in ("path", "relative_path", "change", "entry_type")) and type(w.get("bytes")) is int and (w.get("sha256") is None or type(w.get("sha256")) is str) for w in writes)
if not ok:
    raise RuntimeError("qualification_candidate_audit_scalar_type")
print(j.dumps({
    "canonical_json_sha256": h.sha256(raw).hexdigest(),
    "declared_write_set_sha256": h.sha256(declared).hexdigest(),
    "scalar_types_valid": True,
}, sort_keys=True, separators=(",", ":")))
'''


def _qualification_native_probe_script() -> str:
    """Return an in-memory Win32 binding with no Add-Type/compiler/temp use."""

    return (
        "function Initialize-QrhQualificationNative{"
        "$an=New-Object Reflection.AssemblyName('QrhQualificationNative');"
        "$ab=[AppDomain]::CurrentDomain.DefineDynamicAssembly($an,"
        "[Reflection.Emit.AssemblyBuilderAccess]::Run);"
        "$mb=$ab.DefineDynamicModule('q');$tb=$mb.DefineType('QrhNative',"
        "[Reflection.TypeAttributes]'Public,Sealed,Abstract');"
        "$ma=[Reflection.MethodAttributes]'Public,Static,PinvokeImpl';"
        "$cc=[Reflection.CallingConventions]::Standard;"
        "$wc=[Runtime.InteropServices.CallingConvention]::Winapi;"
        "$uc=[Runtime.InteropServices.CharSet]::Unicode;"
        "function Add-QrhPInvoke([string]$Name,[string]$Dll,[Type]$Return,"
        "[Type[]]$Parameters){$method=$tb.DefinePInvokeMethod($Name,$Dll,$ma,$cc,"
        "$Return,$Parameters,$wc,$uc);$method.SetImplementationFlags("
        "$method.GetMethodImplementationFlags()-bor"
        "[Reflection.MethodImplAttributes]::PreserveSig)};"
        "Add-QrhPInvoke 'FindFirstStreamW' 'kernel32.dll' ([IntPtr]) "
        "([Type[]]@([string],[int],[IntPtr],[int]));"
        "Add-QrhPInvoke 'FindNextStreamW' 'kernel32.dll' ([bool]) "
        "([Type[]]@([IntPtr],[IntPtr]));"
        "Add-QrhPInvoke 'FindClose' 'kernel32.dll' ([bool]) "
        "([Type[]]@([IntPtr]));"
        "Add-QrhPInvoke 'GetLastError' 'kernel32.dll' ([uint32]) ([Type[]]@());"
        "Add-QrhPInvoke 'GetShortPathNameW' 'kernel32.dll' ([uint32]) "
        "([Type[]]@([string],[Text.StringBuilder],[uint32]));"
        "Add-QrhPInvoke 'CommandLineToArgvW' 'shell32.dll' ([IntPtr]) "
        "([Type[]]@([string],[IntPtr]));"
        "Add-QrhPInvoke 'LocalFree' 'kernel32.dll' ([IntPtr]) "
        "([Type[]]@([IntPtr]));return $tb.CreateType()};"
        "$qrhNative=Initialize-QrhQualificationNative;"
        "function Get-QrhRootVariants{"
        "$long=$root.Replace('/','\\').TrimEnd('\\');"
        "$buffer=New-Object Text.StringBuilder(32768);"
        "$length=$qrhNative::GetShortPathNameW($long,$buffer,[uint32]$buffer.Capacity);"
        "if($length-eq 0-or$length-ge$buffer.Capacity)"
        "{throw 'qualification_root_short_path_unavailable'};"
        "$short=$buffer.ToString().Replace('/','\\').TrimEnd('\\');"
        "return @(@($long,$short)|Select-Object -Unique)};"
        "$qrhRootVariants=@(Get-QrhRootVariants);"
        "function Get-QrhWindowsArgv([string]$CommandLine){"
        "if([string]::IsNullOrWhiteSpace($CommandLine))"
        "{throw 'qualification_command_line_absent'};"
        "$count=[Runtime.InteropServices.Marshal]::AllocHGlobal(4);"
        "[Runtime.InteropServices.Marshal]::WriteInt32($count,0);"
        "$pointer=[IntPtr]::Zero;try{$pointer=$qrhNative::CommandLineToArgvW("
        "$CommandLine,$count);$length=[Runtime.InteropServices.Marshal]::ReadInt32($count);"
        "if($pointer-eq[IntPtr]::Zero-or$length-lt 1-or$length-gt 32)"
        "{throw 'qualification_command_line_invalid'};"
        "$values=New-Object 'System.Collections.Generic.List[string]';"
        "for($i=0;$i-lt$length;$i++){$item=[Runtime.InteropServices.Marshal]::ReadIntPtr("
        "$pointer,$i*[IntPtr]::Size);[void]$values.Add("
        "[Runtime.InteropServices.Marshal]::PtrToStringUni($item))};return @($values)}"
        "finally{if($pointer-ne[IntPtr]::Zero){[void]$qrhNative::LocalFree($pointer)};"
        "[Runtime.InteropServices.Marshal]::FreeHGlobal($count)}};"
        "function Test-QrhExactLegacyArgv([object]$CommandLine,[object]$ExecutablePath,"
        "[string]$Server){if($CommandLine-isnot[string]-or"
        "$ExecutablePath-isnot[string]){return $false};try{"
        "$argv=@(Get-QrhWindowsArgv $CommandLine);"
        "$exeFull=[IO.Path]::GetFullPath($ExecutablePath).TrimEnd('\\');"
        "$argvExe=[IO.Path]::GetFullPath([string]$argv[0]).TrimEnd('\\');"
        "$serverFull=[IO.Path]::GetFullPath($Server).TrimEnd('\\');"
        "return $argv.Count-eq 3-and$exeFull.Equals($argvExe,"
        "[StringComparison]::OrdinalIgnoreCase)-and"
        "$argv[1]-eq'-I'-and"
        "([IO.Path]::GetFullPath([string]$argv[2]).TrimEnd('\\')).Equals($serverFull,"
        "[StringComparison]::OrdinalIgnoreCase)}catch{return $false}};"
        "function Test-QrhContainsDRoot([object]$Value){"
        "if($Value-isnot[string]-or[string]::IsNullOrWhiteSpace($Value)){return $false};"
        "$normalized=$Value.Replace('/','\\').Replace('\\\\?\\','');"
        "foreach($candidate in $qrhRootVariants){$start=0;"
        "while($start-lt$normalized.Length){$index=$normalized.IndexOf($candidate,$start,"
        "[StringComparison]::OrdinalIgnoreCase);if($index-lt 0){break};"
        "$beforeOk=$index-eq 0;if(-not$beforeOk){$before=$normalized[$index-1];"
        "$beforeOk=[char]::IsWhiteSpace($before)-or"
        "@([char]34,[char]39,[char]61)-contains$before};"
        "$afterIndex=$index+$candidate.Length;$afterOk=$afterIndex-eq$normalized.Length;"
        "if(-not$afterOk){$after=$normalized[$afterIndex];$afterOk=$after-eq[char]92-or"
        "[char]::IsWhiteSpace($after)-or@([char]34,[char]39)-contains$after};"
        "if($beforeOk-and$afterOk){return $true};$start=$index+1}};return $false};"
        "function Assert-QrhNoAlternateStreams{"
        "$paths=@((Get-Item -LiteralPath $root -Force -ErrorAction Stop))+"
        "@(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop);"
        "$entryCount=0;$buffer=[Runtime.InteropServices.Marshal]::AllocHGlobal(600);try{"
        "foreach($path in $paths){$handle=$qrhNative::FindFirstStreamW("
        "$path.FullName,0,$buffer,0);if($handle-eq[IntPtr](-1)){"
        "$error=$qrhNative::GetLastError();if($error-ne 38)"
        "{throw ('qualification_stream_enumeration_failed:'+$error)};"
        "$entryCount++;continue};"
        "try{while($true){$name=[Runtime.InteropServices.Marshal]::PtrToStringUni("
        "[IntPtr]::Add($buffer,8));if($name-ne'::$DATA')"
        "{throw 'qualification_inventory_alternate_stream'};"
        "if(-not$qrhNative::FindNextStreamW($handle,$buffer)){"
        "$error=$qrhNative::GetLastError();if($error-ne 38)"
        "{throw ('qualification_stream_enumeration_failed:'+$error)};break}}}"
        "finally{[void]$qrhNative::FindClose($handle)};$entryCount++}}finally{"
        "[Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)};return $entryCount};"
    )


def _qualification_replay_guard_script() -> str:
    """Return the exact whole-top-level subset guard used after response loss."""

    return (
        "function Assert-ReplaySnapshot($snapshot){"
        "$expected=@($contract.inspected_top_level_children);"
        "if($expected.Count-lt 1){throw 'qualification_replay_contract_absent'};"
        "$expectedByName=@{};foreach($item in $expected){"
        "$keys=@($item.PSObject.Properties.Name|Sort-Object);"
        "if(($keys-join ',')-ne'inventory_sha256,name'-or"
        "$item.name-notmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'-or"
        "$item.inventory_sha256-notmatch'^[0-9a-f]{64}$'-or"
        "$expectedByName.ContainsKey([string]$item.name))"
        "{throw 'qualification_replay_contract_differs'};"
        "$expectedByName[[string]$item.name]=[string]$item.inventory_sha256};"
        "$actual=@($snapshot.top_level_children);"
        "if($actual.Count-ge$expected.Count){throw 'qualification_replay_not_partial'};"
        "foreach($item in $actual){if(-not$expectedByName.ContainsKey([string]$item.name))"
        "{throw 'qualification_replay_unknown_top_level'};"
        "if($expectedByName[[string]$item.name]-ne[string]$item.inventory_sha256)"
        "{throw 'qualification_replay_partial_child_changed'}}};"
    )


def _qualification_closure_guard_script() -> str:
    """Return the final file/directory closure gate run before D Python."""

    return (
        "function Assert-QrhClosedSnapshot($snapshot,$expectedFiles,$expectedDirectories){"
        "foreach($relative in $snapshot.files.Keys){"
        "if(-not$expectedFiles.Contains($relative)){throw 'qualification_unknown_file'}};"
        "foreach($relative in $snapshot.directories){"
        "if(-not$expectedDirectories.Contains($relative))"
        "{throw 'qualification_unknown_directory'}}};"
    )


def _qualification_candidate_residue_guard_script() -> str:
    """Return the exact failed-candidate audit and empty-residue contract."""

    return (
        "function Assert-QrhCandidateResidueAudit($audit,$snapshot,$expectedDirs){"
        "$directoryChanges=@{audit='modified';'audit/receipts'='created';"
        "backups='created';incoming='created';state='modified';"
        "'state/locks'='created';tmp='modified';'tmp/candidate-probes'='created'};"
        "$sidecars=@('state/comments.sqlite3-wal','state/comments.sqlite3-shm',"
        "'state/research_workspace.sqlite3-wal','state/research_workspace.sqlite3-shm');"
        "$expected=@($directoryChanges.Keys)+$sidecars;$seen=@{};"
        "foreach($write in @($audit.observed_writes)){"
        "$keys=@($write.PSObject.Properties.Name|Sort-Object);"
        "$relative=[string]$write.relative_path;if(($keys-join ',')-ne"
        "'bytes,change,entry_type,path,relative_path,sha256'-or"
        "$seen.ContainsKey($relative)-or$expected-notcontains$relative-or"
        "$write.path-ne($root+'\\'+$relative.Replace('/','\\')))"
        "{throw 'qualification_candidate_audit_write_shape'};"
        "if($directoryChanges.ContainsKey($relative)){if("
        "$write.change-ne$directoryChanges[$relative]-or"
        "$write.entry_type-ne'directory'-or[long]$write.bytes-ne 0-or"
        "$null-ne$write.sha256-or-not$snapshot.directories.Contains($relative))"
            "{throw 'qualification_candidate_audit_directory_shape'}}"
        "else{if($write.change-ne'created'-or$write.entry_type-ne'file'-or"
        "-not$snapshot.files.ContainsKey($relative)-or"
        "[long]$write.bytes-ne[long]$snapshot.files[$relative].bytes-or"
        "[string]$write.sha256-ne[string]$snapshot.files[$relative].sha256)"
            "{throw 'qualification_candidate_audit_file_shape'}};$seen[$relative]=$true};"
        "foreach($relative in $expected){if(-not$seen.ContainsKey($relative))"
        "{throw 'qualification_candidate_audit_residue_unbound'}};"
        "$empty=@('audit/receipts','backups','incoming','state/locks',"
        "'tmp/candidate-probes','tmp/deployment-cli');"
        "foreach($relative in $empty){if(-not$snapshot.directories.Contains($relative))"
            "{throw 'qualification_candidate_directory_absent'};"
        "$cursor=$relative;while($true){[void]$expectedDirs.Add($cursor);"
        "if(-not$cursor.Contains('/')){break};"
        "$cursor=$cursor.Substring(0,$cursor.LastIndexOf('/'))};"
        "$prefix=$relative+'/';foreach($entry in "
        "@(@($snapshot.files.Keys)+@($snapshot.directories))){if("
        "$entry.StartsWith($prefix,[StringComparison]::Ordinal))"
            "{throw 'qualification_candidate_directory_not_empty'}}}};"
    )


def _qualification_legacy_guard_script() -> str:
    """Return the exact listener/process/deployment identity guard."""

    return (
        "function Assert-LegacyV39{"
        "$listeners=@(Get-NetTCPConnection -LocalPort 8765 -State Listen "
        "-ErrorAction Stop);$pids=@($listeners|Select-Object -ExpandProperty "
        "OwningProcess -Unique);if($pids.Count-ne 1){throw 'legacy_listener_identity'};"
        "$process=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$pids[0]) "
        "-ErrorAction Stop);if($process.Count-ne 1){throw 'legacy_process_identity'};"
        "$listenerPid=[int]$pids[0];$command=$process[0].CommandLine;"
        "$executable=$process[0].ExecutablePath;"
        "$server='C:\\quant_platform\\tools\\viewer\\server.py';"
        "if(-not(Test-QrhExactLegacyArgv $command $executable $server))"
        "{throw 'listener_not_exact_legacy_argv'};"
        "$exeFull=[IO.Path]::GetFullPath($executable).TrimEnd('\\');"
        "$exeItem=Get-Item -LiteralPath $exeFull -Force -ErrorAction Stop;"
        "$serverItem=Get-Item -LiteralPath $server -Force -ErrorAction Stop;"
        "$pp=(New-Object Text.UTF8Encoding($false)).GetBytes("
        "$exeFull.ToLowerInvariant());$ph=([BitConverter]::ToString("
        "([Security.Cryptography.SHA256]::Create()).ComputeHash($pp)))."
        "Replace('-','').ToLowerInvariant();"
        "$eh=(Get-FileHash -LiteralPath $exeFull -Algorithm SHA256).Hash."
        "ToLowerInvariant();"
        "$serverHash=(Get-FileHash -LiteralPath $server -Algorithm SHA256).Hash."
        "ToLowerInvariant();"
        "if($exeItem.PSIsContainer-or$serverItem.PSIsContainer-or"
        "(($exeItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)-or"
        "(($serverItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)-or"
        "$ph-ne[string]$contract.python_id[0]-or"
        "$exeItem.Length-ne[long]$contract.python_id[1]-or"
        "$eh-ne[string]$contract.python_id[2]-or"
        "$serverItem.Length-ne[long]$contract.legacy_server_bytes-or"
        "$serverHash-ne([string]$contract.legacy_server_sha256))"
        "{throw 'listener_legacy_authority_differs'};"
        "$response=Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "
        "-Uri 'http://127.0.0.1:8765/deploymentz';"
        "if($response.StatusCode-ne 200){throw 'legacy_deploymentz_status'};"
        "$deployment=$response.Content|ConvertFrom-Json;"
        "$deploymentKeys=@($deployment.PSObject.Properties.Name|Sort-Object);"
        "if(($deploymentKeys-join ',')-ne'deployment_id,pid,port,schema_version,status'-or"
        "$deployment.schema_version-isnot[string]-or$deployment.status-isnot[string]-or"
        "$deployment.deployment_id-isnot[string]-or"
        "$deployment.pid-isnot[int]-and$deployment.pid-isnot[long]-or"
        "$deployment.port-isnot[int]-and$deployment.port-isnot[long]-or"
        "$deployment.schema_version-ne'qrh-company-broadcast-health/v1'-or"
        "$deployment.status-ne'ok'-or$deployment.pid-ne$listenerPid-or"
        "$deployment.port-ne 8765-or"
        "$deployment.deployment_id-ne$contract.legacy_deployment_id)"
        "{throw 'legacy_deployment_id_differs'}};"
    )


def _qualification_no_d_execution_guard_script() -> str:
    """Return the exact service/process/listener absence guard."""

    return (
        "function Assert-NoDExecution{"
        "$services=@(Get-Service -Name 'QuantResearchHub' -ErrorAction SilentlyContinue);"
        "if($services.Count-ne 0){throw 'qualification_service_exists'};"
        "$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop);"
        "foreach($process in $processes){$command=$process.CommandLine;"
        "$executable=$process.ExecutablePath;"
        "if((Test-QrhContainsDRoot $command)-or(Test-QrhContainsDRoot $executable))"
        "{throw 'qualification_d_process_exists'}};"
        "$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop);"
        "foreach($listener in $listeners){$owner=@($processes|Where-Object{"
        "$_.ProcessId-eq$listener.OwningProcess});foreach($process in $owner){"
        "$command=$process.CommandLine;$executable=$process.ExecutablePath;"
        "if((Test-QrhContainsDRoot $command)-or(Test-QrhContainsDRoot $executable))"
        "{throw 'qualification_d_listener_exists'}}}};"
    )


class OpenSSHColdRestore:
    def __init__(
        self,
        config: RuntimePublishConfig,
        *,
        command_runner: Callable[[Sequence[str]], CommandResult] = subprocess_runner,
        bundle_verifier: Callable[[Path], RecoveryVerification] = verify_recovery_bundle,
    ) -> None:
        if config.vm.target_address != "10.5.1.240":
            raise ColdRestoreCLIError("cold restore target must be 10.5.1.240")
        self.config = config
        self.command_runner = command_runner
        self.bundle_verifier = bundle_verifier

    @staticmethod
    def _literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _ssh(
        self, script: str, *, compressed: bool = False,
        compact_qualification_wrapper: bool = False,
    ) -> Mapping[str, object]:
        target_guard = (
            "$ssh=($env:SSH_CONNECTION -split ' ');"
            f"if($ssh.Count-lt 3-or $ssh[2]-ne{self._literal(self.config.vm.target_address)})"
            "{throw 'ssh_target_address_differs'};"
        )
        effective = target_guard + script
        if compressed:
            compressed_bytes = gzip.compress(effective.encode("utf-8"), mtime=0)
            payload = base64.b64encode(compressed_bytes).decode("ascii")
            payload_hash = hashlib.sha256(compressed_bytes).hexdigest()
            length_error = (
                "gz_l" if compact_qualification_wrapper
                else "compressed_script_length_differs"
            )
            hash_error = (
                "gz_h" if compact_qualification_wrapper
                else "compressed_script_hash_differs"
            )
            if compact_qualification_wrapper:
                payload_hash = payload_hash.upper()
                effective = (
                    f"$b=[Convert]::FromBase64String({self._literal(payload)});"
                    f"if($b.Length-ne{len(compressed_bytes)}){{throw 'gz_l'}};"
                    "$d=([BitConverter]::ToString(([Security.Cryptography.SHA256]"
                    "::Create()).ComputeHash($b))).Replace('-','');"
                    f"if($d-ne{self._literal(payload_hash)}){{throw 'gz_h'}};"
                    "$m=[IO.MemoryStream]::new($b);$z=[IO.Compression.GzipStream]"
                    "::new($m,[IO.Compression.CompressionMode]0);"
                    # The payload is locally generated UTF-8 and its exact
                    # compressed bytes are already length/hash bound.  The
                    # one-argument StreamReader constructor is therefore the
                    # same decoder with a materially shorter Windows command.
                    "$r=[IO.StreamReader]::new($z);"
                    # StreamReader owns GZipStream, which owns MemoryStream;
                    # disposing the outer reader closes the complete chain.
                    "try{$s=$r.ReadToEnd()}finally{$r.Dispose()};"
                    "&([scriptblock]::Create($s))"
                )
            else:
                effective = (
                    f"$b=[Convert]::FromBase64String({self._literal(payload)});"
                    f"if($b.Length-ne{len(compressed_bytes)})"
                    f"{{throw {self._literal(length_error)}}};"
                    "$h=[Security.Cryptography.SHA256]::Create();try{"
                    "$d=([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','')."
                    "ToLowerInvariant()}finally{$h.Dispose()};"
                    f"if($d-ne{self._literal(payload_hash)})"
                    f"{{throw {self._literal(hash_error)}}};"
                    "$m=New-Object IO.MemoryStream(,$b);"
                    "$z=New-Object IO.Compression.GzipStream($m,"
                    "[IO.Compression.CompressionMode]::Decompress);"
                    "$r=New-Object IO.StreamReader($z,(New-Object Text.UTF8Encoding($false)));"
                    "try{$s=$r.ReadToEnd()}finally{$r.Dispose();$z.Dispose();$m.Dispose()};"
                    "&([scriptblock]::Create($s))"
                )
        encoded = base64.b64encode(effective.encode("utf-16-le")).decode("ascii")
        result = self.command_runner(
            (
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "--", self.config.vm.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand", encoded,
            )
        )
        if result.returncode != 0:
            raise ColdRestoreCLIError("fixed .240 cold restore command failed")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ColdRestoreCLIError("fixed .240 cold restore response is invalid") from error
        if not isinstance(value, dict):
            raise ColdRestoreCLIError("fixed .240 cold restore response must be an object")
        return value

    @staticmethod
    def _bootstrap_identity(bundle: Path, relative: str) -> tuple[int, str]:
        """Bind a bootstrap executable to the already verified local closure."""

        try:
            inventory = json.loads(
                (bundle / "closure_inventory.json").read_text(encoding="utf-8")
            )
            records = inventory["files"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise ColdRestoreCLIError("verified bundle closure inventory is unreadable") from error
        matching = [
            item
            for item in records
            if isinstance(item, dict) and item.get("path") == relative
        ] if isinstance(records, list) else []
        if len(matching) != 1:
            raise ColdRestoreCLIError("bootstrap file is absent from verified closure")
        record = matching[0]
        expected_size = record.get("bytes")
        expected_hash = record.get("sha256")
        sums: dict[str, str] = {}
        try:
            for line in (bundle / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
                digest, name = line.split("  ", 1)
                if name in sums:
                    raise ValueError("duplicate sum")
                sums[name] = digest
        except (OSError, UnicodeError, ValueError) as error:
            raise ColdRestoreCLIError("verified bundle SHA256SUMS is unreadable") from error
        path = bundle.joinpath(*relative.split("/"))
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
            or sums.get(relative) != expected_hash
            or not path.is_file()
            or path.is_symlink()
        ):
            raise ColdRestoreCLIError("bootstrap identity is not a regular verified file")
        observed_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.stat().st_size != expected_size or observed_hash != expected_hash:
            raise ColdRestoreCLIError("bootstrap bytes changed after bundle verification")
        return expected_size, expected_hash

    @staticmethod
    def _canonical_bytes(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def _write_immutable_evidence(
        cls, path: Path, value: Mapping[str, object]
    ) -> str:
        """Atomically publish canonical evidence, allowing exact-byte retry only."""

        payload = cls._canonical_bytes(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(path.parent)
        ensure_no_reparse_components(path)
        if os.path.lexists(path):
            info = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or path.read_bytes() != payload
            ):
                raise ColdRestoreCLIError("immutable off-host evidence already differs")
            return hashlib.sha256(payload).hexdigest()
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.partial")
        try:
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
                    raise ColdRestoreCLIError("immutable off-host evidence race differs")
            if path.read_bytes() != payload:
                raise ColdRestoreCLIError("immutable off-host evidence publication differs")
            return hashlib.sha256(payload).hexdigest()
        finally:
            temporary.unlink(missing_ok=True)

    @classmethod
    def _preflight_immutable_evidence(
        cls, path: Path, value: Mapping[str, object]
    ) -> None:
        if not os.path.lexists(path):
            return
        ensure_no_reparse_components(path)
        info = path.lstat()
        expected = cls._canonical_bytes(value)
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or path.read_bytes() != expected
        ):
            raise ColdRestoreCLIError("immutable off-host evidence already differs")

    def _recovery_root(self) -> Path:
        recovery = self.config.recovery.recovery_root.resolve(strict=True)
        ensure_no_reparse_components(recovery)
        project = self.config.project_root.resolve()
        if recovery == project or recovery.is_relative_to(project):
            raise ColdRestoreCLIError("recovery evidence authority must remain outside Git")
        return recovery

    def _controlled_evidence_path(self, path: Path, *, category: str) -> Path:
        recovery = self._recovery_root()
        controlled = recovery / "evidence" / category
        controlled.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(controlled)
        target = Path(path).resolve()
        if (
            target.suffix.casefold() != ".json"
            or not target.is_relative_to(controlled.resolve(strict=True))
        ):
            raise ColdRestoreCLIError(
                "evidence output must be a JSON file in the controlled recovery evidence directory"
            )
        ensure_no_reparse_components(target)
        return target

    def _verified_bundle(
        self, bundle_root: Path
    ) -> tuple[Path, RecoveryVerification, str, tuple[int, str], tuple[int, str]]:
        bundle = Path(bundle_root).resolve(strict=True)
        recovery = self._recovery_root()
        ensure_no_reparse_components(bundle)
        if bundle.parent != recovery:
            raise ColdRestoreCLIError("qualification bundle is outside RECOVERY_ROOT")
        report = self.bundle_verifier(bundle)
        if (
            not report.valid
            or not report.bundle_id
            or not report.release_id
            or not report.release_manifest_sha256
            or not report.recovery_manifest_sha256
            or _SHA256.fullmatch(report.release_manifest_sha256) is None
            or _SHA256.fullmatch(report.recovery_manifest_sha256) is None
            or _SAFE_ID.fullmatch(report.bundle_id) is None
        ):
            raise ColdRestoreCLIError("off-host recovery bundle is not verified")
        expected_name = f"cold-recovery-{report.bundle_id}"
        if bundle.name != expected_name:
            raise ColdRestoreCLIError("off-host bundle directory and ID differ")
        restore_name = self.config.recovery.restore_tool.name
        if not restore_name or _SAFE_ID.fullmatch(restore_name) is None:
            raise ColdRestoreCLIError("restore tool filename is unsafe")
        python_identity = self._bootstrap_identity(
            bundle, "operational/tooling/python/python.exe"
        )
        tool_identity = self._bootstrap_identity(
            bundle, f"tools/restore/{restore_name}"
        )
        resealed = self.bundle_verifier(bundle)
        if resealed != report:
            raise ColdRestoreCLIError("off-host bundle identity changed during bootstrap seal")
        if self._bootstrap_identity(
            bundle, "operational/tooling/python/python.exe"
        ) != python_identity or self._bootstrap_identity(
            bundle, f"tools/restore/{restore_name}"
        ) != tool_identity:
            raise ColdRestoreCLIError("bootstrap identity changed during local seal")
        return bundle, report, restore_name, python_identity, tool_identity

    def _qualification_reset_contract(
        self,
        bundle: Path,
        report: RecoveryVerification,
        restore_name: str,
        *,
        expected_legacy_deployment_id: str,
    ) -> Mapping[str, object]:
        """Derive the one-time reset contract from the verified bundle.

        The remote side reads the already materialized release manifest and
        operational bootstrap, after first binding both files to these hashes.
        This keeps the bundle as the only large file inventory authority.
        """

        if expected_legacy_deployment_id != _LEGACY_V39_DEPLOYMENT_ID:
            raise ColdRestoreCLIError(
                "qualification reset is fixed to the exact legacy V39 deployment"
            )
        if (
            not report.checkpoint_id
            or not report.checkpoint_manifest_sha256
            or _SAFE_ID.fullmatch(report.checkpoint_id) is None
            or _SHA256.fullmatch(report.checkpoint_manifest_sha256) is None
        ):
            raise ColdRestoreCLIError(
                "verified qualification checkpoint identity is absent"
            )
        try:
            closure = json.loads(
                (bundle / "closure_inventory.json").read_text(encoding="utf-8")
            )
            closure_bytes = (bundle / "closure_inventory.json").read_bytes()
            closure_sha256 = hashlib.sha256(closure_bytes).hexdigest()
            records = closure["files"]
            by_path = {
                str(item["path"]): item
                for item in records
                if isinstance(item, dict)
            }
            checkpoint_path = (
                bundle / "checkpoints" / str(report.checkpoint_id)
                / "checkpoint_manifest.json"
            )
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            release_manifest_path = bundle / "release" / "release_manifest.json"
            release_manifest = json.loads(
                release_manifest_path.read_text(encoding="utf-8")
            )
            recovery_manifest_path = bundle / "recovery_manifest.json"
            recovery_manifest_bytes = recovery_manifest_path.read_bytes()
            recovery_manifest = json.loads(recovery_manifest_bytes.decode("utf-8"))
            attestation_path = self.config.recovery.attestation_path.resolve(strict=True)
            ensure_no_reparse_components(attestation_path)
            attestation_bytes = attestation_path.read_bytes()
            attestation = json.loads(attestation_bytes.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise ColdRestoreCLIError(
                "verified qualification bundle contract is unreadable"
            ) from error

        def record(relative: str) -> Mapping[str, object]:
            item = by_path.get(relative)
            if (
                not isinstance(item, dict)
                or set(item) != {"path", "bytes", "sha256"}
                or item.get("path") != relative
                or not isinstance(item.get("bytes"), int)
                or isinstance(item.get("bytes"), bool)
                or int(item["bytes"]) < 0
                or not isinstance(item.get("sha256"), str)
                or _SHA256.fullmatch(str(item["sha256"])) is None
            ):
                raise ColdRestoreCLIError(
                    "verified qualification bundle record is invalid"
                )
            return {
                "path": relative,
                "bytes": int(item["bytes"]),
                "sha256": str(item["sha256"]),
            }

        application = release_manifest.get("application")
        release_inventory = release_manifest.get("inventory")
        release_files = (
            release_inventory.get("files")
            if isinstance(release_inventory, dict)
            else None
        )
        legacy_server_records = [
            item
            for item in release_files or []
            if isinstance(item, dict) and item.get("path") == "tools/viewer/server.py"
        ]
        if (
            release_manifest.get("release_id") != report.release_id
            or not isinstance(application, dict)
            or application.get("source_kind") != "legacy_broadcast"
            or application.get("legacy_deployment_id")
            != expected_legacy_deployment_id
            or len(legacy_server_records) != 1
            or set(legacy_server_records[0]) != {"path", "bytes", "sha256"}
            or not isinstance(legacy_server_records[0].get("bytes"), int)
            or isinstance(legacy_server_records[0].get("bytes"), bool)
            or int(legacy_server_records[0]["bytes"]) < 1
            or not isinstance(legacy_server_records[0].get("sha256"), str)
            or _SHA256.fullmatch(str(legacy_server_records[0]["sha256"])) is None
        ):
            raise ColdRestoreCLIError(
                "qualification reset requires the exact legacy V39 bundle"
            )
        try:
            rebuilt = attest_failure_domain(
                production_facts=attestation["production"],
                recovery_facts=attestation["recovery"],
                independence_probe=attestation["independence_probe"],
                observed_at=str(attestation["observed_at"]),
            )
            observed_at = datetime.fromisoformat(
                str(attestation["observed_at"]).replace("Z", "+00:00")
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ColdRestoreCLIError(
                "qualification failure-domain attestation is invalid"
            ) from error
        expected_attestation_fields = {
            "schema_version", "observed_at", "production_host_facts_sha256",
            "recovery_host_facts_sha256", "production", "recovery",
            "independence_probe", "verdict", "attestation_sha256",
        }
        probe = attestation.get("independence_probe")
        production = attestation.get("production")
        recovery = attestation.get("recovery")
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ColdRestoreCLIError(
                "qualification failure-domain timestamp is not timezone-aware"
            )
        age = (datetime.now(UTC) - observed_at.astimezone(UTC)).total_seconds()
        expected_event = {
            "schema_version": "qrh-recovery-materialization-event/v1",
            "event_id": f"cold-materialization-{report.bundle_id}",
            "kind": "cold_recovery_materialized",
            "authority": "evidence_only",
            "fields": {
                "bundle_id": report.bundle_id,
                "release_id": report.release_id,
                "manifest_sha256": report.release_manifest_sha256,
                "empty_root_precondition": True,
                "import_cleaned": True,
                "runtime_tmp_cleaned": True,
            },
        }
        event_path = (
            self._recovery_root() / "evidence" / "cold-materialization"
            / f"{report.bundle_id}.json"
        )
        production_facts_path = (
            attestation_path.parent
            / f"production-host-facts-{report.bundle_id}.json"
        )
        try:
            for formal_path in (event_path, production_facts_path):
                ensure_no_reparse_components(formal_path)
                formal_info = formal_path.lstat()
                if (
                    formal_path.is_symlink()
                    or not stat.S_ISREG(formal_info.st_mode)
                    or formal_info.st_nlink != 1
                ):
                    raise ColdRestoreCLIError(
                        "qualification formally published evidence is not immutable"
                    )
            event_bytes = event_path.read_bytes()
            published_event = json.loads(event_bytes.decode("utf-8"))
            production_facts_bytes = production_facts_path.read_bytes()
            published_production = json.loads(
                production_facts_bytes.decode("utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ColdRestoreCLIError(
                "qualification formally published evidence is unreadable"
            ) from error
        expected_event_bytes = self._canonical_bytes(expected_event)
        legacy_event_bytes = _legacy_materialization_event_bytes(expected_event)
        if len(expected_event_bytes) != len(legacy_event_bytes):
            raise ColdRestoreCLIError(
                "qualification legacy event byte length profile differs"
            )
        expected_facts_bytes = (
            json.dumps(
                production,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if (
            not isinstance(attestation, dict)
            or attestation_bytes != self._canonical_bytes(attestation)
            or set(attestation) != expected_attestation_fields
            or attestation.get("attestation_sha256") != rebuilt.sha256
            or any(
                attestation.get(key) != value
                for key, value in rebuilt.payload.items()
            )
            or not isinstance(probe, dict)
            or probe.get("bundle_id") != report.bundle_id
            or probe.get("release_id") != report.release_id
            or probe.get("release_manifest_sha256")
            != report.release_manifest_sha256
            or probe.get("bundle_inventory_sha256") != closure_sha256
            or probe.get("materialization_event_id") != expected_event["event_id"]
            or probe.get("materialization_event_sha256")
            != hashlib.sha256(expected_event_bytes).hexdigest()
            or published_event != expected_event
            or event_bytes != expected_event_bytes
            or not isinstance(production, dict)
            or published_production != production
            or production_facts_bytes != expected_facts_bytes
            or production.get("canonical_path") != str(self.config.vm.root)
            or production.get("role") != "production"
            or not isinstance(recovery, dict)
            or Path(str(recovery.get("canonical_path"))).resolve(strict=True)
            != self._recovery_root()
            or age < 0
            or age > self.config.recovery.attestation_max_age_seconds
        ):
            raise ColdRestoreCLIError(
                "qualification failure-domain attestation identity differs"
            )
        if (
            hashlib.sha256(recovery_manifest_bytes).hexdigest()
            != report.recovery_manifest_sha256
            or recovery_manifest.get("bundle_id") != report.bundle_id
            or recovery_manifest.get("release")
            != {
                "release_id": report.release_id,
                "manifest_sha256": report.release_manifest_sha256,
            }
            or recovery_manifest.get("checkpoint")
            != {
                "checkpoint_id": report.checkpoint_id,
                "manifest_sha256": report.checkpoint_manifest_sha256,
            }
            or recovery_manifest.get("closure", {}).get("inventory_sha256")
            != closure_sha256
        ):
            raise ColdRestoreCLIError(
                "qualification recovery identity does not bind the attested closure"
            )
        state = checkpoint.get("state")
        databases = state.get("databases") if isinstance(state, dict) else None
        if not isinstance(databases, list):
            raise ColdRestoreCLIError("qualification checkpoint databases are absent")
        state_records: list[dict[str, object]] = []
        for item in databases:
            if not isinstance(item, dict):
                raise ColdRestoreCLIError("qualification checkpoint database is invalid")
            logical_name = item.get("logical_name")
            relative_path = item.get("relative_path")
            size = item.get("size_bytes")
            digest = item.get("sha256")
            if (
                logical_name not in {"comments", "research_workspace"}
                or relative_path != f"state/{logical_name}.sqlite3"
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 100
                or not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
            ):
                raise ColdRestoreCLIError("qualification checkpoint database differs")
            state_records.append(
                {
                    "logical_name": logical_name,
                    "path": f"state/{logical_name}.sqlite3",
                    "bytes": size,
                    "sha256": digest,
                }
            )
        if {item["logical_name"] for item in state_records} != {
            "comments", "research_workspace"
        } or len(state_records) != 2:
            raise ColdRestoreCLIError(
                "qualification checkpoint must contain exactly two state databases"
            )
        active = {
            "schema_version": "qrh-active-release/v1",
            "release_id": report.release_id,
            "release_path": str(self.config.vm.root / "releases" / str(report.release_id)),
            "manifest_sha256": report.release_manifest_sha256,
        }
        active_bytes = self._canonical_bytes(active)
        release_bytes = release_manifest_path.read_bytes()
        if hashlib.sha256(release_bytes).hexdigest() != report.release_manifest_sha256:
            raise ColdRestoreCLIError("qualification release manifest bytes differ")
        checkpoint_bytes = checkpoint_path.read_bytes()
        if hashlib.sha256(checkpoint_bytes).hexdigest() != report.checkpoint_manifest_sha256:
            raise ColdRestoreCLIError("qualification checkpoint manifest bytes differ")
        bootstrap = record("operational/control/operational_bootstrap.json")
        python = record("operational/tooling/python/python.exe")
        tool = record(f"tools/restore/{restore_name}")
        return {
            "schema_version": "qrh-qualification-materialization-reset-contract/v1",
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "release_manifest_bytes": len(release_bytes),
            "checkpoint_id": report.checkpoint_id,
            "checkpoint_manifest_sha256": report.checkpoint_manifest_sha256,
            "recovery_manifest_sha256": report.recovery_manifest_sha256,
            "legacy_deployment_id": _LEGACY_V39_DEPLOYMENT_ID,
            "legacy_python_path_sha256": _LEGACY_V39_PYTHON_PATH_SHA256,
            "legacy_python_bytes": _LEGACY_V39_PYTHON_BYTES,
            "legacy_python_sha256": _LEGACY_V39_PYTHON_SHA256,
            "legacy_server_bytes": int(legacy_server_records[0]["bytes"]),
            "legacy_server_sha256": str(legacy_server_records[0]["sha256"]),
            "closure_inventory_sha256": closure_sha256,
            "recovery_manifest_bytes": len(recovery_manifest_bytes),
            "active_sha256": hashlib.sha256(active_bytes).hexdigest(),
            "active_bytes": len(active_bytes),
            "operational_bootstrap_sha256": bootstrap["sha256"],
            "operational_bootstrap_bytes": bootstrap["bytes"],
            "python_sha256": python["sha256"],
            "python_bytes": python["bytes"],
            "restore_tool_path": f"tools/restore/{restore_name}",
            "restore_tool_sha256": tool["sha256"],
            "restore_tool_bytes": tool["bytes"],
            "state": sorted(state_records, key=lambda item: str(item["logical_name"])),
            "materialization_event_id": f"cold-materialization-{report.bundle_id}",
            "materialization_event_sha256": hashlib.sha256(
                expected_event_bytes
            ).hexdigest(),
            "materialization_event_bytes": len(event_bytes),
            "materialization_event_remote_serialization": (
                _LEGACY_MATERIALIZATION_SERIALIZATION
            ),
            "materialization_event_remote_sha256": hashlib.sha256(
                legacy_event_bytes
            ).hexdigest(),
            "materialization_event_remote_bytes": len(legacy_event_bytes),
            "failure_domain_attestation_sha256": rebuilt.sha256,
            "failure_domain_attestation_file_sha256": hashlib.sha256(
                attestation_bytes
            ).hexdigest(),
            "production_host_facts_sha256": production["facts_sha256"],
            "production_host_facts_relative_path": (
                f"audit/evidence/production-host-facts-{report.bundle_id}.json"
            ),
            "production_host_facts_file_sha256": hashlib.sha256(
                production_facts_bytes
            ).hexdigest(),
            "production_host_facts_bytes": len(production_facts_bytes),
            "declared_write_set_sha256": hashlib.sha256(
                self._canonical_bytes(declared_production_vm_write_set())
            ).hexdigest(),
        }

    def _revalidate_qualification_attestation_file(
        self, contract: Mapping[str, object]
    ) -> None:
        """Re-read the exact canonical attestation bytes before a bound action."""

        expected = contract.get("failure_domain_attestation_file_sha256")
        if not isinstance(expected, str) or _SHA256.fullmatch(expected) is None:
            raise ColdRestoreCLIError(
                "qualification attestation file binding is absent"
            )
        try:
            path = self.config.recovery.attestation_path.resolve(strict=True)
            ensure_no_reparse_components(path)
            info = path.lstat()
            raw = path.read_bytes()
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ColdRestoreCLIError(
                "qualification attestation file cannot be revalidated"
            ) from error
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not isinstance(value, dict)
            or raw != self._canonical_bytes(value)
            or hashlib.sha256(raw).hexdigest() != expected
        ):
            raise ColdRestoreCLIError(
                "qualification attestation file changed or is not canonical"
            )

    def _transfer_attempt(
        self, bundle: Path, report: RecoveryVerification
    ) -> tuple[bytes, int, int, int]:
        """Bind a retryable SCP attempt to one verified, bounded local tree."""

        file_count = 0
        directory_count = 0
        total_bytes = 0
        for path in bundle.rglob("*"):
            ensure_no_reparse_components(path)
            info = path.lstat()
            if path.is_symlink():
                raise ColdRestoreCLIError("verified transfer tree contains a reparse entry")
            if stat.S_ISDIR(info.st_mode):
                directory_count += 1
            elif stat.S_ISREG(info.st_mode):
                file_count += 1
                total_bytes += info.st_size
            else:
                raise ColdRestoreCLIError("verified transfer tree contains a special entry")
        if file_count < 1 or directory_count < 1 or total_bytes < 1:
            raise ColdRestoreCLIError("verified transfer tree has invalid bounds")
        inventory_hash = hashlib.sha256(
            (bundle / "closure_inventory.json").read_bytes()
        ).hexdigest()
        marker = {
            "schema_version": _TRANSFER_ATTEMPT_SCHEMA,
            "bundle_id": report.bundle_id,
            "bundle_directory": bundle.name,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "recovery_manifest_sha256": report.recovery_manifest_sha256,
            "closure_inventory_sha256": inventory_hash,
            "transfer_file_count": file_count,
            "transfer_directory_count": directory_count,
            "transfer_total_bytes": total_bytes,
        }
        return (
            self._canonical_bytes(marker), file_count, directory_count, total_bytes
        )

    def _restore_transfer_prepare_script(
        self,
        *,
        remote_bundle: PureWindowsPath,
        import_parent: PureWindowsPath,
        marker_bytes: bytes,
        maximum_files: int,
        maximum_directories: int,
        maximum_bytes: int,
    ) -> str:
        """Accept an empty root or reset only our own interrupted SCP partial."""

        runtime_tmp = import_parent.parent / "recovery-runtime"
        runtime_work = runtime_tmp / "work"
        marker_path = runtime_tmp / ".cold-restore-attempt.json"
        marker_b64 = base64.b64encode(marker_bytes).decode("ascii")
        return (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;"
            f"$importParent={self._literal(str(import_parent))};"
            f"$remoteBundle={self._literal(str(remote_bundle))};"
            f"$runtimeTmp={self._literal(str(runtime_tmp))};"
            f"$runtimeWork={self._literal(str(runtime_work))};"
            f"$marker={self._literal(str(marker_path))};"
            f"$expectedMarkerB64={self._literal(marker_b64)};"
            f"$maximumFiles=[long]{maximum_files};"
            f"$maximumDirectories=[long]{maximum_directories};"
            f"$maximumBytes=[long]{maximum_bytes};"
            "function Assert-RealDirectory([string]$Path,[string]$Failure){"
            "$item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;"
            "if(-not $item.PSIsContainer-or(($item.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw $Failure}};"
            "function Assert-NoAlternateStreams([string]$Path,[string]$Failure){"
            "$item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;"
            "$streams=@(Get-Item -LiteralPath $Path -Stream * -ErrorAction Stop);"
            "if($item.PSIsContainer){if($streams.Count-ne 0){throw $Failure}}"
            "elseif($streams.Count-ne 1-or$streams[0].Stream-ne':$DATA'){throw $Failure}};"
            "function Assert-LegacyV39{"
            "$listeners=@(Get-NetTCPConnection -LocalPort 8765 -State Listen "
            "-ErrorAction Stop);$pids=@($listeners|Select-Object -ExpandProperty "
            "OwningProcess -Unique);if($pids.Count-ne 1){throw 'retry_legacy_listener_identity'};"
            "$process=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$pids[0]) "
            "-ErrorAction Stop);if($process.Count-ne 1){throw 'retry_legacy_process_identity'};"
            "$command=[string]$process[0].CommandLine;$normalized=$command.Replace('/','\\');"
            "$legacyPrefix=([char]67)+':\\quant_platform\\';"
            "if($normalized.IndexOf($legacyPrefix,"
            "[StringComparison]::OrdinalIgnoreCase)-lt 0-or"
            "$normalized.IndexOf($root,[StringComparison]::OrdinalIgnoreCase)-ge 0)"
            "{throw 'retry_listener_not_legacy_c'};"
            "$response=Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "
            "-Uri 'http://127.0.0.1:8765/deploymentz';"
            "if($response.StatusCode-ne 200){throw 'retry_legacy_deploymentz_status'};"
            "$deployment=$response.Content|ConvertFrom-Json;"
            f"if($deployment.deployment_id-ne{self._literal(_LEGACY_V39_DEPLOYMENT_ID)})"
            "{throw 'retry_legacy_deployment_id_differs'}};"
            "function Write-AttemptMarker{"
            "$bytes=[Convert]::FromBase64String($expectedMarkerB64);"
            "$stream=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,"
            "[IO.FileAccess]::Write,[IO.FileShare]::None);"
            "try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}"
            "finally{$stream.Dispose()}};"
            "function Assert-AttemptMarker{"
            "$item=Get-Item -LiteralPath $marker -Force -ErrorAction Stop;"
            "if($item.PSIsContainer-or(($item.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'retry_marker_type'};"
            "Assert-NoAlternateStreams $marker 'retry_marker_alternate_stream';"
            "$actual=[Convert]::ToBase64String([IO.File]::ReadAllBytes($marker));"
            "if($actual-ne$expectedMarkerB64){throw 'retry_bundle_identity_mismatch'}};"
            "function Assert-SafePartial{"
            "Assert-RealDirectory $remoteBundle 'retry_partial_type';"
            "Assert-NoAlternateStreams $remoteBundle 'retry_partial_alternate_stream';"
            "$bundleFull=[IO.Path]::GetFullPath($remoteBundle).TrimEnd('\\');"
            "$expectedParent=[IO.Path]::GetFullPath($importParent).TrimEnd('\\');"
            "$actualParent=[IO.Path]::GetFullPath((Split-Path -Parent $bundleFull)).TrimEnd('\\');"
            "if(-not $actualParent.Equals($expectedParent,[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'retry_partial_not_exact_child'};"
            "$files=[long]0;$directories=[long]0;$bytes=[long]0;"
            "$items=@(Get-ChildItem -LiteralPath $remoteBundle -Force -Recurse);"
            "foreach($item in $items){"
            "$full=[IO.Path]::GetFullPath($item.FullName);"
            "if(-not $full.StartsWith($bundleFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'retry_partial_path_escape'};"
            "$relative=$full.Substring($bundleFull.Length).TrimStart('\\');"
            "if(-not $relative-or(@($relative -split '\\\\')|Where-Object{"
            "$_-eq'.'-or$_-eq'..'-or$_.Contains(':')}).Count-ne 0)"
            "{throw 'retry_partial_relative_path'};"
            "if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'retry_partial_reparse'};"
            "Assert-NoAlternateStreams $item.FullName 'retry_partial_alternate_stream';"
            "if($item.PSIsContainer){$directories++;continue};"
            "if($item -is [IO.FileInfo]){"
            "$files++;$bytes+=[long]$item.Length}else{throw 'retry_partial_special_entry'}};"
            "if($files-gt$maximumFiles-or$directories-gt$maximumDirectories-or"
            "$bytes-gt$maximumBytes){throw 'retry_partial_exceeds_verified_bounds'}};"
            "function Assert-SafeRuntimeWork{"
            "Assert-RealDirectory $runtimeWork 'retry_runtime_work_type';"
            "$workFull=[IO.Path]::GetFullPath($runtimeWork).TrimEnd('\\');"
            "$expectedParent=[IO.Path]::GetFullPath($runtimeTmp).TrimEnd('\\');"
            "$actualParent=[IO.Path]::GetFullPath((Split-Path -Parent $workFull)).TrimEnd('\\');"
            "if(-not $actualParent.Equals($expectedParent,[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'retry_runtime_work_not_exact_child'};"
            "$files=[long]0;$directories=[long]0;$bytes=[long]0;"
            "$items=@(Get-ChildItem -LiteralPath $runtimeWork -Force -Recurse);"
            "foreach($item in $items){"
            "$full=[IO.Path]::GetFullPath($item.FullName);"
            "if(-not $full.StartsWith($workFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'retry_runtime_work_path_escape'};"
            "if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'retry_runtime_work_reparse'};"
            "if($item.PSIsContainer){$directories++;continue};"
            "if($item -is [IO.FileInfo]){"
            "Assert-NoAlternateStreams $item.FullName 'retry_runtime_work_alternate_stream';"
            "$files++;$bytes+=[long]$item.Length}else{throw 'retry_runtime_work_special_entry'}};"
            "if($files-gt$maximumFiles-or$directories-gt$maximumDirectories-or"
            "$bytes-gt$maximumBytes){throw 'retry_runtime_work_exceeds_verified_bounds'}};"
            "Assert-RealDirectory $root 'retry_exact_root_type';"
            "$active=Join-Path $root 'control\\active_release.json';"
            "$pending=Join-Path $root 'control\\pending_activation.json';"
            "$state=Join-Path $root 'state';$releases=Join-Path $root 'releases';"
            "if((Test-Path -LiteralPath $active)-or(Test-Path -LiteralPath $pending)-or"
            "(Test-Path -LiteralPath $state)-or(Test-Path -LiteralPath $releases))"
            "{throw 'retry_d_authority_or_release_exists'};"
            "$top=@(Get-ChildItem -LiteralPath $root -Force);"
            "if($top.Count-eq 0){"
            "New-Item -ItemType Directory -Force -Path $importParent|Out-Null;"
            "New-Item -ItemType Directory -Force -Path $runtimeTmp|Out-Null;"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;Assert-RealDirectory (Join-Path $root 'tmp') 'new_tmp_type';"
            "Assert-RealDirectory $importParent 'new_import_parent_type';"
            "Assert-RealDirectory $runtimeTmp 'new_runtime_type';Write-AttemptMarker}"
            "else{"
            "if($top.Count-ne 1-or$top[0].Name-ne'tmp')"
            "{throw 'exact_d_root_not_empty_retry_unknown_root_child'};"
            "Assert-RealDirectory $top[0].FullName 'retry_tmp_type';"
            "$tmpChildren=@(Get-ChildItem -LiteralPath $top[0].FullName -Force);"
            "foreach($child in $tmpChildren){if($child.Name-ne'recovery-import'-and"
            "$child.Name-ne'recovery-runtime'){throw 'retry_unknown_tmp_child'}};"
            "if(-not($tmpChildren.Name-contains'recovery-import'))"
            "{throw 'retry_import_parent_absent'};"
            "Assert-RealDirectory $importParent 'retry_import_parent_type';"
            "$importChildren=@(Get-ChildItem -LiteralPath $importParent -Force);"
            "foreach($child in $importChildren){if($child.Name-ne"
            f"{self._literal(remote_bundle.name)}){{throw 'retry_unknown_import_child'}}}};"
            "$hasMarker=Test-Path -LiteralPath $marker;"
            "$hasPartial=Test-Path -LiteralPath $remoteBundle;"
            "if($hasMarker){Assert-AttemptMarker};"
            "if(-not $hasMarker){Assert-LegacyV39};"
            "if(Test-Path -LiteralPath $runtimeTmp){"
            "Assert-RealDirectory $runtimeTmp 'retry_runtime_type';"
            "$runtimeChildren=@(Get-ChildItem -LiteralPath $runtimeTmp -Force);"
            "foreach($child in $runtimeChildren){if($child.Name-ne"
            "'.cold-restore-attempt.json'-and$child.Name-ne'work')"
            "{throw 'retry_unknown_runtime_child'}};"
            "if(Test-Path -LiteralPath $runtimeWork){Assert-SafeRuntimeWork;"
            "Assert-SafeRuntimeWork;Remove-Item -LiteralPath $runtimeWork -Recurse -Force}}"
            "else{New-Item -ItemType Directory -Force -Path $runtimeTmp|Out-Null;"
            "Assert-RealDirectory $runtimeTmp 'retry_runtime_type'};"
            "if($hasPartial){Assert-SafePartial;"
            "$partial=Get-Item -LiteralPath $remoteBundle -Force -ErrorAction Stop;"
            "$partialParent=[IO.Path]::GetFullPath((Split-Path -Parent $partial.FullName)).TrimEnd('\\');"
            "$expectedParent=[IO.Path]::GetFullPath($importParent).TrimEnd('\\');"
            "if(-not $partialParent.Equals($expectedParent,[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'retry_delete_target_not_exact_child'};"
            "Assert-SafePartial;"
            "Remove-Item -LiteralPath $partial.FullName -Recurse -Force};"
            "if(-not $hasMarker){Write-AttemptMarker};"
            "$remaining=@(Get-ChildItem -LiteralPath $importParent -Force);"
            "if($remaining.Count-ne 0)"
            "{throw 'retry_cleanup_not_closed'};"
            "$runtimeRemaining=@(Get-ChildItem -LiteralPath $runtimeTmp -Force);"
            "if($runtimeRemaining.Count-ne 1-or"
            "$runtimeRemaining[0].Name-ne'.cold-restore-attempt.json')"
            "{throw 'retry_runtime_cleanup_not_closed'}};"
            "@{status='prepared_empty_root';empty_root_precondition=$true}"
            "|ConvertTo-Json -Compress"
        )

    def _prepare_empty_script(
        self,
        *,
        expected_legacy_deployment_id: str,
        intent_nonce_sha256: str,
        apply: bool,
        expected_inventory_sha256: str | None,
    ) -> str:
        if _SAFE_ID.fullmatch(expected_legacy_deployment_id) is None:
            raise ColdRestoreCLIError("expected legacy deployment ID is invalid")
        if _SHA256.fullmatch(intent_nonce_sha256) is None:
            raise ColdRestoreCLIError("prepare-empty intent nonce hash is invalid")
        if apply:
            if (
                not isinstance(expected_inventory_sha256, str)
                or _SHA256.fullmatch(expected_inventory_sha256) is None
            ):
                raise ColdRestoreCLIError("expected pre-delete inventory hash is invalid")
        elif expected_inventory_sha256 is not None:
            raise ColdRestoreCLIError("inspection cannot claim a pre-delete inventory hash")
        allowed = ",".join(
            self._literal(name) for name in sorted(PRODUCTION_WRITE_AREAS)
        )
        expected_hash = self._literal(expected_inventory_sha256 or "")
        expected_deployment = self._literal(expected_legacy_deployment_id)
        intent_hash = self._literal(intent_nonce_sha256)
        schema = _PREPARE_APPLY_SCHEMA if apply else _PREPARE_INSPECTION_SCHEMA
        common = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;"
            f"$allowed=@({allowed});"
            f"$expectedHash={expected_hash};$expectedDeployment={expected_deployment};"
            f"$intentHash={intent_hash};"
            "function Get-CanonicalRootInventory{"
            "$rootItem=Get-Item -LiteralPath $root -Force -ErrorAction Stop;"
            "if(-not $rootItem.PSIsContainer -or (($rootItem.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'exact_root_type'};"
            "$top=@(Get-ChildItem -LiteralPath $root -Force);"
            "foreach($item in $top){if($allowed -notcontains $item.Name)"
            "{throw 'unknown_top_level'};if(($item.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'top_level_reparse'}};"
            "$records=New-Object 'System.Collections.Generic.List[string]';"
            "$files=0;$directories=0;$bytes=[long]0;"
            "$all=@(Get-ChildItem -LiteralPath $root -Force -Recurse);"
            "foreach($item in $all){if(($item.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'inventory_reparse'};"
            "$relative=$item.FullName.Substring($root.Length).TrimStart('\\').Replace('\\','/');"
            "if(-not $relative -or $relative.Contains('../') -or $relative.Contains(':'))"
            "{throw 'inventory_relative_path'};"
            "if($item.PSIsContainer){$directories++;[void]$records.Add('D'+[char]9+"
            "$relative+[char]10)}else{$files++;$bytes+=$item.Length;"
            "$hash=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash."
            "ToLowerInvariant();[void]$records.Add('F'+[char]9+$relative+[char]9+"
            "$item.Length+[char]9+$hash+[char]10)}};"
            "$records.Sort([StringComparer]::Ordinal);$text=[string]::Concat($records);"
            "$payload=(New-Object Text.UTF8Encoding($false)).GetBytes($text);"
            "$hasher=[Security.Cryptography.SHA256]::Create();try{"
            "$hash=([BitConverter]::ToString($hasher.ComputeHash($payload))).Replace('-','')."
            "ToLowerInvariant()}finally{$hasher.Dispose()};"
            "return [pscustomobject]@{inventory_sha256=$hash;file_count=$files;"
            "directory_count=$directories;total_bytes=$bytes;top_level_count=$top.Count}};"
            "function Assert-NoDWriter{"
            "$active=Join-Path $root 'control\\active_release.json';"
            "if(Test-Path -LiteralPath $active){throw 'd_active_authority_exists'};"
            "$pending=Join-Path $root 'control\\pending_activation.json';"
            "if(Test-Path -LiteralPath $pending){throw 'd_pending_activation_exists'};"
            "$state=Join-Path $root 'state';if(Test-Path -LiteralPath $state){"
            "$stateItem=Get-Item -LiteralPath $state -Force;"
            "if(-not $stateItem.PSIsContainer -or (($stateItem.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'd_state_type'};"
            "if(@(Get-ChildItem -LiteralPath $state -Force).Count -ne 0)"
            "{throw 'd_state_writer_authority_exists'}}};"
            "function Assert-LegacyV39{"
            "$listeners=@(Get-NetTCPConnection -LocalPort 8765 -State Listen "
            "-ErrorAction Stop);$pids=@($listeners|Select-Object -ExpandProperty OwningProcess -Unique);"
            "if($pids.Count -ne 1){throw 'legacy_listener_identity'};"
            "$process=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$pids[0]) "
            "-ErrorAction Stop);if($process.Count -ne 1){throw 'legacy_process_identity'};"
            "$command=[string]$process[0].CommandLine;$normalized=$command.Replace('/','\\');"
            "if($normalized.IndexOf('C:\\quant_platform\\',"
            "[StringComparison]::OrdinalIgnoreCase) -lt 0 -or "
            "$normalized.IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0)"
            "{throw 'listener_not_legacy_c'};"
            "$response=Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "
            "-Uri 'http://127.0.0.1:8765/deploymentz';"
            "if($response.StatusCode -ne 200){throw 'legacy_deploymentz_status'};"
            "$deployment=$response.Content|ConvertFrom-Json;"
            "if($deployment.deployment_id -ne $expectedDeployment)"
            "{throw 'legacy_deployment_id_differs'}};"
            "Assert-NoDWriter;Assert-LegacyV39;$inventory=Get-CanonicalRootInventory;"
        )
        if not apply:
            return common + (
                "[ordered]@{"
                f"schema_version={self._literal(schema)};status='inspected_not_deleted';"
                "intent_nonce_sha256=$intentHash;"
                "inventory_sha256=$inventory.inventory_sha256;file_count=$inventory.file_count;"
                "directory_count=$inventory.directory_count;total_bytes=$inventory.total_bytes;"
                "top_level_count=$inventory.top_level_count;legacy_deployment_id=$expectedDeployment;"
                "active_absent=$true;writer_authority_absent=$true;old_c_v39_healthy=$true;"
                "deleted=$false}|ConvertTo-Json -Compress"
            )
        return common + (
            "if($inventory.inventory_sha256 -ne $expectedHash){throw 'pre_delete_inventory_differs'};"
            "Assert-NoDWriter;Assert-LegacyV39;$second=Get-CanonicalRootInventory;"
            "if($second.inventory_sha256 -ne $expectedHash){throw 'pre_delete_inventory_changed'};"
            "$children=@(Get-ChildItem -LiteralPath $root -Force|Sort-Object FullName);"
            "foreach($child in $children){$full=[IO.Path]::GetFullPath($child.FullName);"
            "$parent=[IO.Path]::GetFullPath((Split-Path -Parent $full)).TrimEnd('\\');"
            "if(-not $parent.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or "
            "$full.Equals($root,[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'delete_target_not_exact_child'};"
            "$current=Get-Item -LiteralPath $full -Force -ErrorAction Stop;"
            "if(($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)"
            "{throw 'delete_target_reparse'};if($allowed -notcontains $current.Name)"
            "{throw 'delete_target_unknown'}};"
            "$third=Get-CanonicalRootInventory;if($third.inventory_sha256 -ne $expectedHash)"
            "{throw 'pre_delete_inventory_changed_after_child_preflight'};"
            "$confirmed=@(Get-ChildItem -LiteralPath $root -Force|Sort-Object FullName);"
            "if(($children.FullName -join [char]10) -ne ($confirmed.FullName -join [char]10))"
            "{throw 'pre_delete_child_set_changed'};"
            "foreach($child in $children){$current=Get-Item -LiteralPath $child.FullName "
            "-Force -ErrorAction Stop;if(($current.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'delete_target_reparse'};"
            "Remove-Item -LiteralPath $child.FullName -Recurse -Force};"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;$postRoot=Get-Item -LiteralPath $root -Force -ErrorAction Stop;"
            "if(-not $postRoot.PSIsContainer -or (($postRoot.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0) -or "
            "@(Get-ChildItem -LiteralPath $root -Force).Count -ne 0)"
            "{throw 'exact_root_not_empty_after_prepare'};"
            "Assert-LegacyV39;[ordered]@{"
            f"schema_version={self._literal(schema)};status='prepared_empty_root';"
            "intent_nonce_sha256=$intentHash;"
            "pre_delete_inventory_sha256=$expectedHash;deleted_child_count=$children.Count;"
            "legacy_deployment_id=$expectedDeployment;root_exists=$true;root_empty=$true;"
            "old_c_v39_healthy=$true;active_absent=$true;writer_authority_absent=$true}"
            "|ConvertTo-Json -Compress"
        )

    def _qualification_reset_script(
        self,
        *,
        contract: Mapping[str, object],
        intent_nonce_sha256: str,
        apply: bool,
        expected_inventory_sha256: str | None,
    ) -> str:
        """Inspect/reset one exact, materialized, never-activated V39 root."""

        if _SHA256.fullmatch(intent_nonce_sha256) is None:
            raise ColdRestoreCLIError("qualification reset nonce hash is invalid")
        if apply:
            if (
                not isinstance(expected_inventory_sha256, str)
                or _SHA256.fullmatch(expected_inventory_sha256) is None
            ):
                raise ColdRestoreCLIError(
                    "qualification reset inventory hash is invalid"
                )
        elif expected_inventory_sha256 is not None:
            raise ColdRestoreCLIError(
                "qualification reset inspection cannot claim an inventory hash"
            )
        remote_fields = {
            "active_bytes", "active_sha256", "bundle_id",
            "declared_write_set_sha256", "legacy_deployment_id",
            "legacy_python_path_sha256", "legacy_python_bytes",
            "legacy_python_sha256",
            "legacy_server_bytes", "legacy_server_sha256",
            "materialization_event_bytes", "operational_bootstrap_bytes",
            "operational_bootstrap_sha256", "production_host_facts_bytes",
            "production_host_facts_file_sha256", "python_bytes", "python_sha256",
            "release_id", "release_manifest_bytes", "release_manifest_sha256",
            "restore_tool_bytes", "restore_tool_path", "restore_tool_sha256", "state",
        }
        if apply:
            remote_fields.add("inspected_top_level_children")
        else:
            remote_fields.update({
                "production_host_facts_relative_path",
                "materialization_event_remote_sha256",
            })
        if not remote_fields.issubset(contract):
            raise ColdRestoreCLIError("qualification reset remote contract is incomplete")
        remote_contract = {key: contract[key] for key in sorted(remote_fields)}
        remote_contract["python_id"] = [
            remote_contract.pop("legacy_python_path_sha256"),
            remote_contract.pop("legacy_python_bytes"),
            remote_contract.pop("legacy_python_sha256"),
        ]
        contract_bytes = self._canonical_bytes(remote_contract)
        contract_literal = self._literal(contract_bytes.decode("utf-8"))
        # The destructive application consumes the immutable inspection hash and
        # never executes D tooling.  Canonical audit execution is inspection-only,
        # after that inspection has closed the whole root twice.
        probe_assignment = (
            f"$probeSource={self._literal(_CANONICAL_AUDIT_PROBE)};"
            if not apply else ""
        )
        audit_probe_script = (
            "function Invoke-QualificationAuditProbe([string]$AuditRelative){"
            "$python=Join-Path $root 'tooling\\python\\python.exe';"
            "$pythonItem=Get-Item -LiteralPath $python -Force -ErrorAction Stop;"
            "if($pythonItem.PSIsContainer-or(($pythonItem.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)-or"
            "$pythonItem.Length-ne[long]$contract.python_bytes)"
            "{throw 'qualification_python_identity_differs'};"
            "$pythonHash=(Get-FileHash -LiteralPath $python -Algorithm SHA256).Hash."
            "ToLowerInvariant();if($pythonHash-ne[string]$contract.python_sha256)"
            "{throw 'qualification_python_identity_differs'};"
            "$audit=Join-Path $root $AuditRelative.Replace('/','\\');"
            "$probeEncoded=[Convert]::ToBase64String("
            "[Text.Encoding]::UTF8.GetBytes($probeSource));"
            "$bootstrap=\"import base64,sys;exec(compile(base64.b64decode("
            "sys.argv.pop(1)),'<qualification-audit-probe>','exec'))\";"
            "$oldBytecode=$env:PYTHONDONTWRITEBYTECODE;"
            "$oldPreference=$ErrorActionPreference;try{"
            "$env:PYTHONDONTWRITEBYTECODE='1';$ErrorActionPreference='Continue';"
            "$raw=&$python -I -B -c $bootstrap $probeEncoded $root $audit 2>&1;"
            "$probeExit=$LASTEXITCODE}finally{$ErrorActionPreference=$oldPreference;"
            "$env:PYTHONDONTWRITEBYTECODE=$oldBytecode};if($probeExit-ne 0){throw "
            "('qualification_audit_probe_failed:'+[string]($raw-join ' '))};"
            "$value=([string]($raw-join ''))|ConvertFrom-Json;"
            "$keys=@($value.PSObject.Properties.Name|Sort-Object);"
            "if(($keys-join ',')-ne'canonical_json_sha256,declared_write_set_sha256,"
            "scalar_types_valid'-or$value.scalar_types_valid-ne$true)"
            "{throw 'qualification_audit_probe_shape'};return $value};"
            if not apply else ""
        )
        residue_guard_script = (
            _qualification_candidate_residue_guard_script() if not apply else ""
        )
        expected_hash = self._literal(expected_inventory_sha256 or "")
        intent_hash = self._literal(intent_nonce_sha256)
        empty_release_suffixes = ",".join(
            relative.removeprefix("runtime/")
            for relative in _LEGACY_V39_EMPTY_RELEASE_DIRECTORIES
        )
        schema = (
            _QUALIFICATION_RESET_APPLY_SCHEMA
            if apply else _QUALIFICATION_RESET_INSPECTION_SCHEMA
        )
        common = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;"
            + f"$contractJson={contract_literal};"
            + probe_assignment
            + f"$expectedHash={expected_hash};$intentHash={intent_hash};"
            "$contract=$contractJson|ConvertFrom-Json;"
            + _qualification_native_probe_script()
            + _qualification_legacy_guard_script()
            + _qualification_no_d_execution_guard_script()
            + audit_probe_script
            + residue_guard_script
            + "function Get-CanonicalRootInventory{"
            "$rootItem=Get-Item -LiteralPath $root -Force -ErrorAction Stop;"
            "if(-not$rootItem.PSIsContainer-or(($rootItem.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'exact_root_type'};"
            "$records=New-Object 'System.Collections.Generic.List[string]';"
            "$files=@{};$directories=New-Object 'System.Collections.Generic.HashSet[string]' "
            "([StringComparer]::Ordinal);$fileCount=0;$directoryCount=0;$bytes=[long]0;"
            "$all=@(Get-ChildItem -LiteralPath $root -Force -Recurse);"
            "foreach($item in $all){if(($item.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'qualification_inventory_reparse'};"
            "$relative=$item.FullName.Substring($root.Length).TrimStart('\\').Replace('\\','/');"
            "if(-not$relative-or$relative.Contains('../')-or$relative.Contains(':'))"
            "{throw 'qualification_inventory_relative_path'};"
            "if($item.PSIsContainer){$directoryCount++;[void]$directories.Add($relative);"
            "[void]$records.Add('D'+[char]9+$relative+[char]10);continue};"
            "$fileCount++;$bytes+=[long]$item.Length;"
            "$hash=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash."
            "ToLowerInvariant();if($files.ContainsKey($relative))"
            "{throw 'qualification_duplicate_path'};"
            "$files[$relative]=[pscustomobject]@{bytes=[long]$item.Length;sha256=$hash};"
            "[void]$records.Add('F'+[char]9+$relative+[char]9+$item.Length+[char]9+"
            "$hash+[char]10)};"
            "$streamCount=Assert-QrhNoAlternateStreams;"
            "if([long]$streamCount-ne([long]$fileCount+[long]$directoryCount+1))"
            "{throw 'qualification_win32_probe_entry_count'};"
            "$records.Sort([StringComparer]::Ordinal);$text=[string]::Concat($records);"
            "$payload=(New-Object Text.UTF8Encoding($false)).GetBytes($text);"
            "$hasher=[Security.Cryptography.SHA256]::Create();try{"
            "$hash=([BitConverter]::ToString($hasher.ComputeHash($payload))).Replace('-','')."
            "ToLowerInvariant()}finally{$hasher.Dispose()};"
            "$topChildren=New-Object 'System.Collections.Generic.List[object]';"
            "$top=@(Get-ChildItem -LiteralPath $root -Force|Sort-Object Name);"
            "foreach($child in $top){$name=[string]$child.Name;"
            "$childRecords=@($records|Where-Object{$record=[string]$_;"
            "$parts=$record.Split([char]9);if($parts.Count-lt 2){$false}else{"
            "$relative=$parts[1].TrimEnd([char]10);$relative-eq$name-or"
            "$relative.StartsWith($name+'/',[StringComparison]::Ordinal)}});"
            "$childText=[string]::Concat($childRecords);"
            "$childPayload=(New-Object Text.UTF8Encoding($false)).GetBytes($childText);"
            "$childHasher=[Security.Cryptography.SHA256]::Create();try{"
            "$childHash=([BitConverter]::ToString($childHasher.ComputeHash($childPayload)))."
            "Replace('-','').ToLowerInvariant()}finally{$childHasher.Dispose()};"
            "[void]$topChildren.Add([pscustomobject]@{name=$name;"
            "inventory_sha256=$childHash})};"
            "return [pscustomobject]@{inventory_sha256=$hash;files=$files;"
            "directories=$directories;file_count=$fileCount;directory_count=$directoryCount;"
            "total_bytes=$bytes;top_level_count=$top.Count;"
            # Windows PowerShell 5.1 raises System.ArgumentException when an
            # array subexpression directly wraps List[object] inside a
            # PSCustomObject literal.  ToArray preserves the same insertion
            # order and element identities without invoking that broken
            # binder path.
            "top_level_children=$topChildren.ToArray()}};"
            + _qualification_replay_guard_script()
            + _qualification_closure_guard_script()
            +
            "function Assert-OriginalTopClosure($snapshot){"
            "$expected=@($contract.inspected_top_level_children);"
            "$actual=@($snapshot.top_level_children);if($expected.Count-ne$actual.Count)"
            "{throw 'qualification_original_top_count_differs'};"
            "for($i=0;$i-lt$expected.Count;$i++){if("
            "[string]$expected[$i].name-ne[string]$actual[$i].name-or"
            "[string]$expected[$i].inventory_sha256-ne"
            "[string]$actual[$i].inventory_sha256)"
            "{throw 'qualification_original_top_closure_differs'}}};"
            "function Assert-QualificationSnapshot($snapshot){"
            "$expectedFiles=New-Object 'System.Collections.Generic.HashSet[string]' "
            "([StringComparer]::Ordinal);$expectedDirectories=New-Object "
            "'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal);"
            "function Add-ExpectedFile([string]$Relative,[long]$Bytes,[string]$Sha256){"
            "if(-not$snapshot.files.ContainsKey($Relative)){throw 'qualification_expected_file_absent'};"
            "$observed=$snapshot.files[$Relative];if($observed.bytes-ne$Bytes-or"
            "$observed.sha256-ne$Sha256){throw 'qualification_expected_file_differs'};"
            "if(-not$expectedFiles.Add($Relative)){throw 'qualification_duplicate_expected_file'};"
            "$cursor=$Relative;while($cursor.Contains('/')){$cursor=$cursor.Substring(0,"
            "$cursor.LastIndexOf('/'));[void]$expectedDirectories.Add($cursor)}};"
            "$releaseBase='releases/'+$contract.release_id;"
            "$releaseManifest=$releaseBase+'/release_manifest.json';"
            "Add-ExpectedFile $releaseManifest ([long]$contract.release_manifest_bytes) "
            "([string]$contract.release_manifest_sha256);"
            "$releasePath=Join-Path $root $releaseManifest.Replace('/','\\');"
            "$manifest=[IO.File]::ReadAllText($releasePath,(New-Object Text.UTF8Encoding($false)))"
            "|ConvertFrom-Json;if($manifest.schema_version-ne'qrh-release-manifest/v1'-or"
            "$manifest.release_id-ne$contract.release_id){throw 'qualification_release_identity'};"
            "$releaseRecords=@($manifest.inventory.files);if($releaseRecords.Count-lt 1)"
            "{throw 'qualification_release_inventory_empty'};foreach($record in $releaseRecords){"
            "Add-ExpectedFile ($releaseBase+'/'+[string]$record.path) ([long]$record.bytes) "
            "([string]$record.sha256)};"
            f"foreach($r in {self._literal(empty_release_suffixes)}.Split(',')){{"
            "[void]$expectedDirectories.Add($releaseBase+'/runtime/'+$r)};"
            "$bootstrap='control/operational_bootstrap.json';"
            "Add-ExpectedFile $bootstrap ([long]$contract.operational_bootstrap_bytes) "
            "([string]$contract.operational_bootstrap_sha256);"
            "$bootstrapPath=Join-Path $root $bootstrap.Replace('/','\\');"
            "$operational=[IO.File]::ReadAllText($bootstrapPath,(New-Object "
            "Text.UTF8Encoding($false)))|ConvertFrom-Json;"
            "if($operational.schema_version-ne'qrh-operational-bootstrap/v1'-or"
            "$operational.authority_root-ne$root){throw 'qualification_operational_identity'};"
            "foreach($record in @($operational.files)){"
            "$relative=[string]$record.path;if(-not($relative.StartsWith('tooling/')-or"
            "$relative.StartsWith('control/'))){throw 'qualification_operational_path'};"
            "Add-ExpectedFile $relative ([long]$record.bytes) ([string]$record.sha256)};"
            "Add-ExpectedFile 'control/active_release.json' ([long]$contract.active_bytes) "
            "([string]$contract.active_sha256);"
            "foreach($record in @($contract.state)){Add-ExpectedFile ([string]$record.path) "
            "([long]$record.bytes) ([string]$record.sha256)};"
            "Add-ExpectedFile ([string]$contract.restore_tool_path) "
            "([long]$contract.restore_tool_bytes) ([string]$contract.restore_tool_sha256);"
            "$eventRelative='audit/events/cold-materialization-'+$contract.bundle_id+'.json';"
            "Add-ExpectedFile $eventRelative "
            "([long]$contract.materialization_event_bytes) "
            "([string]$contract.materialization_event_remote_sha256);"
            "$factsRelative=[string]$contract.production_host_facts_relative_path;"
            "Add-ExpectedFile $factsRelative ([long]$contract.production_host_facts_bytes) "
            "([string]$contract.production_host_facts_file_sha256);"
            "$writeAudits=@($snapshot.files.Keys|Where-Object{"
            "$_.StartsWith('audit/events/vm-write-audit-')-and$_.EndsWith('.json')});"
            "if($writeAudits.Count-ne 1){throw 'qualification_candidate_audit_count'};"
            "foreach($auditRelative in $writeAudits){"
            "$auditPath=Join-Path $root $auditRelative.Replace('/','\\');"
            "$audit=[IO.File]::ReadAllText($auditPath,(New-Object Text.UTF8Encoding($false)))"
            "|ConvertFrom-Json;$keys=@($audit.PSObject.Properties.Name|Sort-Object);"
            "if(($keys-join ',')-ne'audit_id,audit_record_path,authority_root,declared_write_set,"
            "observed_writes,operation,outcome,schema_version,verdict'-or"
            "$audit.schema_version-ne'qrh-production-vm-write-audit/v1'-or"
            "$audit.operation-ne'deploy-candidate_only'-or$audit.outcome-ne'failed'-or"
            "$audit.authority_root-ne$root-or$audit.verdict-ne'pass'-or"
            "$audit.audit_id-notmatch'^vm-write-audit-[0-9a-f]{32}$'-or"
            "$auditRelative-ne('audit/events/'+$audit.audit_id+'.json')-or"
            "$audit.audit_record_path-ne($root+'\\'+$auditRelative.Replace('/','\\')))"
            "{throw 'qualification_candidate_audit_identity'};"
            "Assert-QrhCandidateResidueAudit $audit $snapshot $expectedDirectories;"
            "$auditRecord=$snapshot.files[$auditRelative];Add-ExpectedFile $auditRelative "
            "([long]$auditRecord.bytes) ([string]$auditRecord.sha256)};"
            "$sidecars=@('state/comments.sqlite3-wal','state/comments.sqlite3-shm',"
            "'state/research_workspace.sqlite3-wal','state/research_workspace.sqlite3-shm');"
            "foreach($name in @('comments','research_workspace')){"
            "$wal='state/'+$name+'.sqlite3-wal';$shm='state/'+$name+'.sqlite3-shm';"
            "$hasWal=$snapshot.files.ContainsKey($wal);$hasShm=$snapshot.files.ContainsKey($shm);"
            "if(-not$hasWal-or-not$hasShm){throw 'qualification_candidate_sidecar_pair_incomplete'};"
            "if($snapshot.files[$wal].bytes-ne 0-or"
            "$snapshot.files[$wal].sha256-ne"
            "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')"
            "{throw 'qualification_candidate_sidecar_wal_nonzero'};"
            "if($snapshot.files[$shm].bytes-ne 32768)"
            "{throw 'qualification_candidate_sidecar_shm_shape'};"
            "[void]$expectedFiles.Add($wal);[void]$expectedFiles.Add($shm)};"
            "Assert-QrhClosedSnapshot $snapshot $expectedFiles $expectedDirectories;"
            "$canonicalAudit=Invoke-QualificationAuditProbe $auditRelative;"
            "if($canonicalAudit.canonical_json_sha256-ne"
            "$snapshot.files[$auditRelative].sha256)"
            "{throw 'qualification_candidate_audit_canonical_hash'};"
            "if($canonicalAudit.declared_write_set_sha256-ne"
            "$contract.declared_write_set_sha256)"
            "{throw 'qualification_candidate_audit_declared_set'}};"
            "Assert-NoDExecution;Assert-LegacyV39;"
        )
        if apply:
            # Apply is byte-identity-only: the immutable off-host inspection
            # already ran the semantic/root closure twice.  Keep replay and
            # original-top guards, but do not ship unreachable inspect-only
            # code or execute any D tooling during deletion/retry.
            common = common.replace(_qualification_closure_guard_script(), "", 1)
            start = common.index("function Assert-QualificationSnapshot($snapshot){")
            end = common.index("Assert-NoDExecution;Assert-LegacyV39;", start)
            common = common[:start] + common[end:]
        else:
            # Inspection cannot be a response-loss replay and therefore has no
            # use for the destructive-only subset/original-top guards.
            common = common.replace(_qualification_replay_guard_script(), "", 1)
            start = common.index("function Assert-OriginalTopClosure($snapshot){")
            end = common.index("function Assert-QualificationSnapshot($snapshot){", start)
            common = common[:start] + common[end:]
        common += "$first=Get-CanonicalRootInventory;"
        if apply:
            common += (
                "$isReplay=$first.inventory_sha256-ne$expectedHash;"
                "if($isReplay){Assert-ReplaySnapshot $first}"
                "else{Assert-OriginalTopClosure $first};"
                "if($first.top_level_count-eq 0){Assert-NoDExecution;Assert-LegacyV39;"
                "$emptyAgain=Get-CanonicalRootInventory;Assert-ReplaySnapshot $emptyAgain;"
                "if($emptyAgain.inventory_sha256-ne$first.inventory_sha256)"
                "{throw 'qualification_empty_root_changed'};"
                "Assert-NoDExecution;Assert-LegacyV39;[ordered]@{"
                f"schema_version={self._literal(schema)};status='prepared_empty_root';"
                "intent_nonce_sha256=$intentHash;pre_delete_inventory_sha256=$expectedHash;"
                "remaining_pre_delete_inventory_sha256=$first.inventory_sha256;"
                "deleted_child_count=0;remaining_child_count=0;"
                "legacy_deployment_id=$contract.legacy_deployment_id;"
                "bundle_id=$contract.bundle_id;root_exists=$true;root_empty=$true;"
                "old_c_v39_healthy=$true;service_absent=$true;d_execution_absent=$true;"
                "qualification_reset_materialized=$true;never_activated=$true;"
                "response_recovered=$true}|ConvertTo-Json -Compress;exit};"
            )
        else:
            common += "Assert-QualificationSnapshot $first;"
        common += (
            "Assert-NoDExecution;Assert-LegacyV39;"
            "$second=Get-CanonicalRootInventory;"
        )
        if apply:
            common += (
                "if($isReplay){Assert-ReplaySnapshot $second}"
                "else{Assert-OriginalTopClosure $second};"
            )
        else:
            common += "Assert-QualificationSnapshot $second;"
        common += (
            "if($first.inventory_sha256-ne$second.inventory_sha256)"
            "{throw 'qualification_inventory_changed_during_inspection'};"
        )
        if not apply:
            return common + (
                "[ordered]@{"
                f"schema_version={self._literal(schema)};status='inspected_not_deleted';"
                "intent_nonce_sha256=$intentHash;inventory_sha256=$second.inventory_sha256;"
                "file_count=$second.file_count;directory_count=$second.directory_count;"
                "total_bytes=$second.total_bytes;top_level_count=$second.top_level_count;"
                "top_level_children=@($second.top_level_children);"
                "legacy_deployment_id=$contract.legacy_deployment_id;"
                "bundle_id=$contract.bundle_id;old_c_v39_healthy=$true;service_absent=$true;"
                "d_execution_absent=$true;qualification_reset_materialized=$true;"
                "never_activated=$true;deleted=$false}|ConvertTo-Json -Compress"
            )
        return common + (
            "if(-not$isReplay-and$second.inventory_sha256-ne$expectedHash)"
            "{throw 'qualification_pre_delete_inventory_differs'};"
            "Assert-NoDExecution;Assert-LegacyV39;"
            "$third=Get-CanonicalRootInventory;if($isReplay){Assert-ReplaySnapshot $third}"
            "else{Assert-OriginalTopClosure $third};"
            "if($third.inventory_sha256-ne$second.inventory_sha256)"
            "{throw 'qualification_pre_delete_inventory_changed'};"
            "$children=@(Get-ChildItem -LiteralPath $root -Force|Sort-Object FullName);"
            "foreach($child in $children){$full=[IO.Path]::GetFullPath($child.FullName);"
            "$parent=[IO.Path]::GetFullPath((Split-Path -Parent $full)).TrimEnd('\\');"
            "if(-not$parent.Equals($root,[StringComparison]::OrdinalIgnoreCase)-or"
            "$full.Equals($root,[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'qualification_delete_target_not_exact_child'};"
            "$current=Get-Item -LiteralPath $full -Force -ErrorAction Stop;"
            "if(($current.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'qualification_delete_target_reparse'}};"
            "$fourth=Get-CanonicalRootInventory;if($isReplay){Assert-ReplaySnapshot $fourth}"
            "else{Assert-OriginalTopClosure $fourth};"
            "if($fourth.inventory_sha256-ne$second.inventory_sha256)"
            "{throw 'qualification_pre_delete_inventory_changed_after_child_preflight'};"
            "$confirmed=@(Get-ChildItem -LiteralPath $root -Force|Sort-Object FullName);"
            "if(($children.FullName-join[char]10)-ne($confirmed.FullName-join[char]10))"
            "{throw 'qualification_pre_delete_child_set_changed'};"
            "Assert-NoDExecution;Assert-LegacyV39;"
            "foreach($child in $children){$current=Get-Item -LiteralPath $child.FullName "
            "-Force -ErrorAction Stop;if(($current.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'qualification_delete_target_reparse'};"
            "Remove-Item -LiteralPath $child.FullName -Recurse -Force};"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;$postRoot=Get-Item -LiteralPath $root -Force -ErrorAction Stop;"
            "if(-not$postRoot.PSIsContainer-or(($postRoot.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)-or"
            "@(Get-ChildItem -LiteralPath $root -Force).Count-ne 0)"
            "{throw 'qualification_exact_root_not_empty_after_prepare'};"
            "Assert-NoDExecution;Assert-LegacyV39;Assert-NoDExecution;Assert-LegacyV39;"
            "[ordered]@{"
            f"schema_version={self._literal(schema)};status='prepared_empty_root';"
            "intent_nonce_sha256=$intentHash;pre_delete_inventory_sha256=$expectedHash;"
            "remaining_pre_delete_inventory_sha256=$second.inventory_sha256;"
            "deleted_child_count=$children.Count;legacy_deployment_id=$contract.legacy_deployment_id;"
            "remaining_child_count=0;"
            "bundle_id=$contract.bundle_id;root_exists=$true;root_empty=$true;"
            "old_c_v39_healthy=$true;service_absent=$true;d_execution_absent=$true;"
            "qualification_reset_materialized=$true;never_activated=$true;"
            "response_recovered=$isReplay}|ConvertTo-Json -Compress"
        )

    @staticmethod
    def _prepare_identity(value: Mapping[str, object], *, apply: bool) -> None:
        schema = _PREPARE_APPLY_SCHEMA if apply else _PREPARE_INSPECTION_SCHEMA
        status = "prepared_empty_root" if apply else "inspected_not_deleted"
        if value.get("schema_version") != schema or value.get("status") != status:
            raise ColdRestoreCLIError("prepare-empty remote evidence schema differs")
        if value.get("legacy_deployment_id") is None:
            raise ColdRestoreCLIError("prepare-empty legacy identity is absent")
        if (
            not isinstance(value.get("intent_nonce_sha256"), str)
            or _SHA256.fullmatch(str(value["intent_nonce_sha256"])) is None
        ):
            raise ColdRestoreCLIError("prepare-empty nonce binding is absent")
        if apply:
            count = value.get("deleted_child_count")
            if (
                not isinstance(value.get("pre_delete_inventory_sha256"), str)
                or _SHA256.fullmatch(str(value["pre_delete_inventory_sha256"])) is None
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count < 0
                or any(
                    value.get(field) is not True
                    for field in (
                        "root_exists", "root_empty", "old_c_v39_healthy",
                        "active_absent", "writer_authority_absent",
                    )
                )
            ):
                raise ColdRestoreCLIError("prepare-empty post-delete gates differ")
        else:
            counts = tuple(
                value.get(field)
                for field in (
                    "file_count", "directory_count", "total_bytes", "top_level_count"
                )
            )
            if (
                not isinstance(value.get("inventory_sha256"), str)
                or _SHA256.fullmatch(str(value["inventory_sha256"])) is None
                or value.get("deleted") is not False
                or any(
                    not isinstance(count, int)
                    or isinstance(count, bool)
                    or count < 0
                    for count in counts
                )
                or any(
                    value.get(field) is not True
                    for field in (
                        "old_c_v39_healthy", "active_absent",
                        "writer_authority_absent",
                    )
                )
            ):
                raise ColdRestoreCLIError("prepare-empty inspection gates differ")

    @staticmethod
    def _qualification_reset_identity(
        value: Mapping[str, object], *, apply: bool
    ) -> None:
        schema = (
            _QUALIFICATION_RESET_APPLY_SCHEMA
            if apply else _QUALIFICATION_RESET_INSPECTION_SCHEMA
        )
        status = "prepared_empty_root" if apply else "inspected_not_deleted"
        if value.get("schema_version") != schema or value.get("status") != status:
            raise ColdRestoreCLIError(
                "qualification reset remote evidence schema differs"
            )
        if any(
            value.get(field) is not True
            for field in (
                "old_c_v39_healthy", "service_absent", "d_execution_absent",
                "qualification_reset_materialized", "never_activated",
            )
        ):
            raise ColdRestoreCLIError("qualification reset remote gates differ")
        if (
            not isinstance(value.get("intent_nonce_sha256"), str)
            or _SHA256.fullmatch(str(value["intent_nonce_sha256"])) is None
            or not isinstance(value.get("bundle_id"), str)
            or _SAFE_ID.fullmatch(str(value["bundle_id"])) is None
            or not isinstance(value.get("legacy_deployment_id"), str)
            or value.get("legacy_deployment_id") != _LEGACY_V39_DEPLOYMENT_ID
        ):
            raise ColdRestoreCLIError("qualification reset identity is absent")
        if apply:
            if (
                not isinstance(value.get("pre_delete_inventory_sha256"), str)
                or _SHA256.fullmatch(
                    str(value["pre_delete_inventory_sha256"])
                ) is None
                or not isinstance(value.get("deleted_child_count"), int)
                or isinstance(value.get("deleted_child_count"), bool)
                or int(value["deleted_child_count"]) < 0
                or not isinstance(value.get("remaining_child_count"), int)
                or isinstance(value.get("remaining_child_count"), bool)
                or int(value["remaining_child_count"]) != 0
                or not isinstance(
                    value.get("remaining_pre_delete_inventory_sha256"), str
                )
                or _SHA256.fullmatch(
                    str(value["remaining_pre_delete_inventory_sha256"])
                ) is None
                or value.get("root_exists") is not True
                or value.get("root_empty") is not True
                or not isinstance(value.get("response_recovered"), bool)
            ):
                raise ColdRestoreCLIError(
                    "qualification reset post-delete gates differ"
                )
        elif (
            not isinstance(value.get("inventory_sha256"), str)
            or _SHA256.fullmatch(str(value["inventory_sha256"])) is None
            or value.get("deleted") is not False
            or any(
                not isinstance(value.get(field), int)
                or isinstance(value.get(field), bool)
                or int(value[field]) < 0
                for field in (
                    "file_count", "directory_count", "total_bytes", "top_level_count"
                )
            )
        ):
            raise ColdRestoreCLIError(
                "qualification reset inspection gates differ"
            )
        if not apply:
            children = value.get("top_level_children")
            if (
                not isinstance(children, list)
                or len(children) != value.get("top_level_count")
                or not children
            ):
                raise ColdRestoreCLIError(
                    "qualification reset top-level closure is absent"
                )
            names: list[str] = []
            for child in children:
                if (
                    not isinstance(child, dict)
                    or set(child) != {"name", "inventory_sha256"}
                    or not isinstance(child.get("name"), str)
                    or _SAFE_ID.fullmatch(str(child["name"])) is None
                    or not isinstance(child.get("inventory_sha256"), str)
                    or _SHA256.fullmatch(str(child["inventory_sha256"])) is None
                ):
                    raise ColdRestoreCLIError(
                        "qualification reset top-level closure differs"
                    )
                names.append(str(child["name"]))
            if names != sorted(names) or len(names) != len(set(names)):
                raise ColdRestoreCLIError(
                    "qualification reset top-level closure is not canonical"
                )

    def _inspect_qualification_reset(
        self,
        bundle_root: Path,
        *,
        intent_nonce: str,
        expected_legacy_deployment_id: str,
    ) -> Mapping[str, object]:
        bundle, report, restore_name, _python, _tool = self._verified_bundle(
            bundle_root
        )
        if len(intent_nonce) < 16 or _SAFE_ID.fullmatch(intent_nonce) is None:
            raise ColdRestoreCLIError("qualification reset intent nonce is invalid")
        if expected_legacy_deployment_id != _LEGACY_V39_DEPLOYMENT_ID:
            raise ColdRestoreCLIError(
                "qualification reset is fixed to the exact legacy V39 deployment"
            )
        contract = self._qualification_reset_contract(
            bundle,
            report,
            restore_name,
            expected_legacy_deployment_id=expected_legacy_deployment_id,
        )
        nonce_hash = hashlib.sha256(intent_nonce.encode("utf-8")).hexdigest()
        evidence = (
            self._recovery_root() / "evidence"
            / "prepare-empty-qualification-reset"
            / f"{nonce_hash}.inspection.json"
        )
        if os.path.lexists(evidence):
            raise ColdRestoreCLIError(
                "qualification reset intent nonce was already inspected"
            )
        result = self._ssh(
            self._qualification_reset_script(
                contract=contract,
                intent_nonce_sha256=nonce_hash,
                apply=False,
                expected_inventory_sha256=None,
            ),
            compressed=True,
            compact_qualification_wrapper=True,
        )
        self._qualification_reset_identity(result, apply=False)
        if any(
            (
                result.get("legacy_deployment_id")
                != expected_legacy_deployment_id,
                result.get("intent_nonce_sha256") != nonce_hash,
                result.get("bundle_id") != report.bundle_id,
            )
        ):
            raise ColdRestoreCLIError("qualification reset inspection binding differs")
        self._revalidate_qualification_attestation_file(contract)
        recorded = {
            "schema_version": (
                "qrh-prepare-empty-qualification-reset-offhost-inspection/v1"
            ),
            "authority": "evidence_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "intent_nonce_sha256": nonce_hash,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "checkpoint_id": report.checkpoint_id,
            "checkpoint_manifest_sha256": report.checkpoint_manifest_sha256,
            "recovery_manifest_sha256": report.recovery_manifest_sha256,
            "materialization_event_id": contract["materialization_event_id"],
            "materialization_event_sha256": contract[
                "materialization_event_sha256"
            ],
            "materialization_event_remote_serialization": contract[
                "materialization_event_remote_serialization"
            ],
            "materialization_event_remote_sha256": contract[
                "materialization_event_remote_sha256"
            ],
            "materialization_event_remote_bytes": contract[
                "materialization_event_remote_bytes"
            ],
            "failure_domain_attestation_sha256": contract[
                "failure_domain_attestation_sha256"
            ],
            "failure_domain_attestation_file_sha256": contract[
                "failure_domain_attestation_file_sha256"
            ],
            "production_host_facts_sha256": contract[
                "production_host_facts_sha256"
            ],
            "production_host_facts_file_sha256": contract[
                "production_host_facts_file_sha256"
            ],
            "closure_inventory_sha256": contract["closure_inventory_sha256"],
            "legacy_deployment_id": _LEGACY_V39_DEPLOYMENT_ID,
            "legacy_python_path_sha256": contract["legacy_python_path_sha256"],
            "legacy_python_bytes": contract["legacy_python_bytes"],
            "legacy_python_sha256": contract["legacy_python_sha256"],
            "pre_delete_inventory_sha256": result["inventory_sha256"],
            "top_level_children": result["top_level_children"],
            "remote_gates": {
                "qualification_reset_materialized": True,
                "never_activated": True,
                "service_absent": True,
                "d_execution_absent": True,
                "old_c_v39_healthy": True,
                "deleted": False,
            },
        }
        evidence_hash = self._write_immutable_evidence(evidence, recorded)
        return {
            "status": "inspected_not_deleted",
            "qualification_reset_materialized": True,
            "intent_nonce_sha256": nonce_hash,
            "pre_delete_inventory_sha256": result["inventory_sha256"],
            "legacy_deployment_id": _LEGACY_V39_DEPLOYMENT_ID,
            "bundle_id": report.bundle_id,
            "evidence_sha256": evidence_hash,
        }

    def _apply_qualification_reset(
        self,
        bundle_root: Path,
        *,
        intent_nonce: str,
        expected_pre_delete_inventory_sha256: str,
        expected_legacy_deployment_id: str,
    ) -> Mapping[str, object]:
        bundle, report, restore_name, _python, _tool = self._verified_bundle(
            bundle_root
        )
        if len(intent_nonce) < 16 or _SAFE_ID.fullmatch(intent_nonce) is None:
            raise ColdRestoreCLIError("qualification reset intent nonce is invalid")
        if _SHA256.fullmatch(expected_pre_delete_inventory_sha256) is None:
            raise ColdRestoreCLIError(
                "qualification reset inventory hash is invalid"
            )
        if expected_legacy_deployment_id != _LEGACY_V39_DEPLOYMENT_ID:
            raise ColdRestoreCLIError(
                "qualification reset is fixed to the exact legacy V39 deployment"
            )
        contract = self._qualification_reset_contract(
            bundle,
            report,
            restore_name,
            expected_legacy_deployment_id=expected_legacy_deployment_id,
        )
        nonce_hash = hashlib.sha256(intent_nonce.encode("utf-8")).hexdigest()
        evidence_root = (
            self._recovery_root() / "evidence"
            / "prepare-empty-qualification-reset"
        )
        inspection_path = evidence_root / f"{nonce_hash}.inspection.json"
        try:
            ensure_no_reparse_components(inspection_path)
            inspection_info = inspection_path.lstat()
            inspection_bytes = inspection_path.read_bytes()
            inspection = json.loads(inspection_bytes.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ColdRestoreCLIError(
                "matching qualification reset inspection evidence is absent"
            ) from error
        remote_gates = {
            "qualification_reset_materialized": True,
            "never_activated": True,
            "service_absent": True,
            "d_execution_absent": True,
            "old_c_v39_healthy": True,
            "deleted": False,
        }
        expected_inspection = {
            "intent_nonce_sha256": nonce_hash,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "checkpoint_id": report.checkpoint_id,
            "checkpoint_manifest_sha256": report.checkpoint_manifest_sha256,
            "recovery_manifest_sha256": report.recovery_manifest_sha256,
            "materialization_event_id": contract["materialization_event_id"],
            "materialization_event_sha256": contract[
                "materialization_event_sha256"
            ],
            "materialization_event_remote_serialization": contract[
                "materialization_event_remote_serialization"
            ],
            "materialization_event_remote_sha256": contract[
                "materialization_event_remote_sha256"
            ],
            "materialization_event_remote_bytes": contract[
                "materialization_event_remote_bytes"
            ],
            "failure_domain_attestation_sha256": contract[
                "failure_domain_attestation_sha256"
            ],
            "failure_domain_attestation_file_sha256": contract[
                "failure_domain_attestation_file_sha256"
            ],
            "production_host_facts_sha256": contract[
                "production_host_facts_sha256"
            ],
            "production_host_facts_file_sha256": contract[
                "production_host_facts_file_sha256"
            ],
            "closure_inventory_sha256": contract["closure_inventory_sha256"],
            "legacy_deployment_id": _LEGACY_V39_DEPLOYMENT_ID,
            "legacy_python_path_sha256": contract["legacy_python_path_sha256"],
            "legacy_python_bytes": contract["legacy_python_bytes"],
            "legacy_python_sha256": contract["legacy_python_sha256"],
            "pre_delete_inventory_sha256": expected_pre_delete_inventory_sha256,
            "top_level_children": inspection.get("top_level_children"),
        }
        if (
            inspection_path.is_symlink()
            or not stat.S_ISREG(inspection_info.st_mode)
            or inspection_info.st_nlink != 1
            or not isinstance(inspection, dict)
            or inspection_bytes != self._canonical_bytes(inspection)
            or set(inspection) != {
                "schema_version", "authority", "recorded_at", "remote_gates",
                *expected_inspection,
            }
            or inspection.get("schema_version")
            != "qrh-prepare-empty-qualification-reset-offhost-inspection/v1"
            or inspection.get("authority") != "evidence_only"
            or inspection.get("remote_gates") != remote_gates
            or any(
                inspection.get(key) != value
                for key, value in expected_inspection.items()
            )
        ):
            raise ColdRestoreCLIError(
                "qualification reset inspection does not authorize this deletion"
            )
        self._revalidate_qualification_attestation_file(contract)
        intent_path = evidence_root / f"{nonce_hash}.apply-intent.json"
        applied_path = evidence_root / f"{nonce_hash}.applied.json"
        if os.path.lexists(applied_path):
            raise ColdRestoreCLIError(
                "qualification reset intent nonce was already applied"
            )
        intent_static = {
            **expected_inspection,
            "inspection_evidence_sha256": hashlib.sha256(inspection_bytes).hexdigest(),
        }
        if os.path.lexists(intent_path):
            try:
                ensure_no_reparse_components(intent_path)
                intent_info = intent_path.lstat()
                intent_bytes = intent_path.read_bytes()
                intent = json.loads(intent_bytes.decode("utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ColdRestoreCLIError(
                    "qualification reset apply intent is invalid"
                ) from error
            if (
                intent_path.is_symlink()
                or not stat.S_ISREG(intent_info.st_mode)
                or intent_info.st_nlink != 1
                or not isinstance(intent, dict)
                or intent_bytes != self._canonical_bytes(intent)
                or set(intent) != {
                    "schema_version", "authority", "recorded_at", *intent_static,
                }
                or intent.get("schema_version")
                != "qrh-prepare-empty-qualification-reset-offhost-apply-intent/v1"
                or intent.get("authority") != "coordination_only"
                or any(intent.get(key) != value for key, value in intent_static.items())
            ):
                raise ColdRestoreCLIError(
                    "qualification reset apply intent retry differs"
                )
            intent_hash = hashlib.sha256(intent_bytes).hexdigest()
        else:
            intent = {
                "schema_version": (
                    "qrh-prepare-empty-qualification-reset-offhost-apply-intent/v1"
                ),
                "authority": "coordination_only",
                "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                **intent_static,
            }
            intent_hash = self._write_immutable_evidence(intent_path, intent)
        contract = {
            **contract,
            "inspected_top_level_children": inspection["top_level_children"],
        }
        self._revalidate_qualification_attestation_file(contract)
        result = self._ssh(
            self._qualification_reset_script(
                contract=contract,
                intent_nonce_sha256=nonce_hash,
                apply=True,
                expected_inventory_sha256=expected_pre_delete_inventory_sha256,
            ),
            compressed=True,
            compact_qualification_wrapper=True,
        )
        self._qualification_reset_identity(result, apply=True)
        if any(
            (
                result.get("legacy_deployment_id")
                != expected_legacy_deployment_id,
                result.get("intent_nonce_sha256") != nonce_hash,
                result.get("bundle_id") != report.bundle_id,
                result.get("pre_delete_inventory_sha256")
                != expected_pre_delete_inventory_sha256,
            )
        ):
            raise ColdRestoreCLIError("qualification reset apply binding differs")
        applied = {
            "schema_version": (
                "qrh-prepare-empty-qualification-reset-offhost-applied/v1"
            ),
            "authority": "evidence_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            **expected_inspection,
            "apply_intent_sha256": intent_hash,
            "root_exists": True,
            "root_empty": True,
            "old_c_v39_healthy": True,
            "response_recovered": bool(result["response_recovered"]),
            "remaining_pre_delete_inventory_sha256": result[
                "remaining_pre_delete_inventory_sha256"
            ],
            "remaining_child_count": result["remaining_child_count"],
            "deleted_child_count": result["deleted_child_count"],
        }
        applied_hash = self._write_immutable_evidence(applied_path, applied)
        return {
            "status": "prepared_empty_root",
            "qualification_reset_materialized": True,
            "intent_nonce_sha256": nonce_hash,
            "pre_delete_inventory_sha256": expected_pre_delete_inventory_sha256,
            "legacy_deployment_id": _LEGACY_V39_DEPLOYMENT_ID,
            "bundle_id": report.bundle_id,
            "response_recovered": bool(result["response_recovered"]),
            "remaining_pre_delete_inventory_sha256": result[
                "remaining_pre_delete_inventory_sha256"
            ],
            "remaining_child_count": result["remaining_child_count"],
            "deleted_child_count": result["deleted_child_count"],
            "evidence_sha256": applied_hash,
        }

    def inspect_prepare_empty(
        self,
        bundle_root: Path,
        *,
        intent_nonce: str,
        expected_legacy_deployment_id: str,
        qualification_reset_materialized: bool = False,
    ) -> Mapping[str, object]:
        if qualification_reset_materialized:
            return self._inspect_qualification_reset(
                bundle_root,
                intent_nonce=intent_nonce,
                expected_legacy_deployment_id=expected_legacy_deployment_id,
            )
        _bundle, report, _restore, _python, _tool = self._verified_bundle(bundle_root)
        if len(intent_nonce) < 16 or _SAFE_ID.fullmatch(intent_nonce) is None:
            raise ColdRestoreCLIError("prepare-empty intent nonce is invalid")
        nonce_hash = hashlib.sha256(intent_nonce.encode("utf-8")).hexdigest()
        evidence = self._recovery_root() / "evidence" / "prepare-empty" / (
            f"{nonce_hash}.inspection.json"
        )
        if os.path.lexists(evidence):
            raise ColdRestoreCLIError("prepare-empty intent nonce was already inspected")
        result = self._ssh(
            self._prepare_empty_script(
                expected_legacy_deployment_id=expected_legacy_deployment_id,
                intent_nonce_sha256=nonce_hash,
                apply=False,
                expected_inventory_sha256=None,
            )
        )
        self._prepare_identity(result, apply=False)
        if (
            result.get("legacy_deployment_id") != expected_legacy_deployment_id
            or result.get("intent_nonce_sha256") != nonce_hash
        ):
            raise ColdRestoreCLIError("prepare-empty legacy deployment binding differs")
        recorded = {
            "schema_version": "qrh-prepare-empty-offhost-inspection/v1",
            "authority": "evidence_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "intent_nonce_sha256": nonce_hash,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "legacy_deployment_id": expected_legacy_deployment_id,
            "pre_delete_inventory_sha256": result["inventory_sha256"],
            "remote_gates": {
                "active_absent": True,
                "writer_authority_absent": True,
                "old_c_v39_healthy": True,
                "deleted": False,
            },
        }
        evidence_hash = self._write_immutable_evidence(evidence, recorded)
        return {
            "status": "inspected_not_deleted",
            "intent_nonce_sha256": nonce_hash,
            "pre_delete_inventory_sha256": result["inventory_sha256"],
            "legacy_deployment_id": expected_legacy_deployment_id,
            "bundle_id": report.bundle_id,
            "evidence_sha256": evidence_hash,
        }

    def apply_prepare_empty(
        self,
        bundle_root: Path,
        *,
        intent_nonce: str,
        expected_pre_delete_inventory_sha256: str,
        expected_legacy_deployment_id: str,
        qualification_reset_materialized: bool = False,
    ) -> Mapping[str, object]:
        if qualification_reset_materialized:
            return self._apply_qualification_reset(
                bundle_root,
                intent_nonce=intent_nonce,
                expected_pre_delete_inventory_sha256=(
                    expected_pre_delete_inventory_sha256
                ),
                expected_legacy_deployment_id=expected_legacy_deployment_id,
            )
        _bundle, report, _restore, _python, _tool = self._verified_bundle(bundle_root)
        if len(intent_nonce) < 16 or _SAFE_ID.fullmatch(intent_nonce) is None:
            raise ColdRestoreCLIError("prepare-empty intent nonce is invalid")
        if _SHA256.fullmatch(expected_pre_delete_inventory_sha256) is None:
            raise ColdRestoreCLIError("expected pre-delete inventory hash is invalid")
        if _SAFE_ID.fullmatch(expected_legacy_deployment_id) is None:
            raise ColdRestoreCLIError("expected legacy deployment ID is invalid")
        nonce_hash = hashlib.sha256(intent_nonce.encode("utf-8")).hexdigest()
        evidence_root = self._recovery_root() / "evidence" / "prepare-empty"
        inspection_path = evidence_root / f"{nonce_hash}.inspection.json"
        try:
            ensure_no_reparse_components(inspection_path)
            inspection_info = inspection_path.lstat()
            inspection_bytes = inspection_path.read_bytes()
            inspection = json.loads(inspection_bytes.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ColdRestoreCLIError("matching append-only inspection evidence is absent") from error
        if (
            inspection_path.is_symlink()
            or not stat.S_ISREG(inspection_info.st_mode)
            or inspection_info.st_nlink != 1
            or not isinstance(inspection, dict)
            or inspection_bytes != self._canonical_bytes(inspection)
            or set(inspection) != {
                "schema_version", "authority", "recorded_at",
                "intent_nonce_sha256", "bundle_id", "release_id",
                "release_manifest_sha256", "legacy_deployment_id",
                "pre_delete_inventory_sha256", "remote_gates",
            }
            or inspection.get("schema_version")
            != "qrh-prepare-empty-offhost-inspection/v1"
            or inspection.get("authority") != "evidence_only"
            or inspection.get("remote_gates")
            != {
                "active_absent": True,
                "writer_authority_absent": True,
                "old_c_v39_healthy": True,
                "deleted": False,
            }
        ):
            raise ColdRestoreCLIError("matching append-only inspection evidence is invalid")
        expected_inspection = {
            "intent_nonce_sha256": nonce_hash,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "legacy_deployment_id": expected_legacy_deployment_id,
            "pre_delete_inventory_sha256": expected_pre_delete_inventory_sha256,
        }
        if any(inspection.get(key) != value for key, value in expected_inspection.items()):
            raise ColdRestoreCLIError("inspection evidence does not authorize this deletion")
        intent_path = evidence_root / f"{nonce_hash}.apply-intent.json"
        applied_path = evidence_root / f"{nonce_hash}.applied.json"
        if os.path.lexists(applied_path):
            raise ColdRestoreCLIError("prepare-empty intent nonce was already applied")
        intent = {
            "schema_version": "qrh-prepare-empty-offhost-apply-intent/v1",
            "authority": "coordination_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            **expected_inspection,
            "inspection_evidence_sha256": hashlib.sha256(
                inspection_path.read_bytes()
            ).hexdigest(),
        }
        intent_hash = self._write_immutable_evidence(intent_path, intent)
        result = self._ssh(
            self._prepare_empty_script(
                expected_legacy_deployment_id=expected_legacy_deployment_id,
                intent_nonce_sha256=nonce_hash,
                apply=True,
                expected_inventory_sha256=expected_pre_delete_inventory_sha256,
            )
        )
        self._prepare_identity(result, apply=True)
        if (
            result.get("legacy_deployment_id") != expected_legacy_deployment_id
            or result.get("intent_nonce_sha256") != nonce_hash
            or result.get("pre_delete_inventory_sha256")
            != expected_pre_delete_inventory_sha256
        ):
            raise ColdRestoreCLIError("prepare-empty apply binding differs")
        applied = {
            "schema_version": "qrh-prepare-empty-offhost-applied/v1",
            "authority": "evidence_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            **expected_inspection,
            "apply_intent_sha256": intent_hash,
            "root_exists": True,
            "root_empty": True,
            "old_c_v39_healthy": True,
        }
        applied_hash = self._write_immutable_evidence(applied_path, applied)
        return {
            "status": "prepared_empty_root",
            "intent_nonce_sha256": nonce_hash,
            "pre_delete_inventory_sha256": expected_pre_delete_inventory_sha256,
            "legacy_deployment_id": expected_legacy_deployment_id,
            "bundle_id": report.bundle_id,
            "evidence_sha256": applied_hash,
        }

    def restore(
        self, bundle_root: Path, *, evidence_output: Path
    ) -> Mapping[str, object]:
        bundle, report, restore_name, python_identity, tool_identity = (
            self._verified_bundle(bundle_root)
        )
        python_size, python_hash = python_identity
        tool_size, tool_hash = tool_identity
        evidence_path = self._controlled_evidence_path(
            evidence_output, category="cold-materialization"
        )
        audit_id = f"cold-materialization-{report.bundle_id}"
        expected_event = {
            "schema_version": "qrh-recovery-materialization-event/v1",
            "event_id": audit_id,
            "kind": "cold_recovery_materialized",
            "authority": "evidence_only",
            "fields": {
                "bundle_id": report.bundle_id,
                "release_id": report.release_id,
                "manifest_sha256": report.release_manifest_sha256,
                "empty_root_precondition": True,
                "import_cleaned": True,
                "runtime_tmp_cleaned": True,
            },
        }
        # A conflicting local authority must block before the first remote
        # write. Exact existing bytes are the sole idempotent case.
        self._preflight_immutable_evidence(evidence_path, expected_event)
        import_parent = self.config.vm.root / "tmp" / "recovery-import"
        runtime_tmp = self.config.vm.root / "tmp" / "recovery-runtime"
        expected_name = bundle.name
        remote_bundle = import_parent / expected_name
        marker_bytes, maximum_files, maximum_directories, maximum_bytes = (
            self._transfer_attempt(bundle, report)
        )
        prepare = self._restore_transfer_prepare_script(
            remote_bundle=remote_bundle,
            import_parent=import_parent,
            marker_bytes=marker_bytes,
            maximum_files=maximum_files,
            maximum_directories=maximum_directories,
            maximum_bytes=maximum_bytes,
        )
        prepared = self._ssh(prepare)
        if prepared != {"status": "prepared_empty_root", "empty_root_precondition": True}:
            raise ColdRestoreCLIError("exact .240 D root empty precondition did not pass")
        copied = self.command_runner(
            (
                "scp", "-q", "-r", "-o", "BatchMode=yes", "-o",
                "ConnectTimeout=20", "-o",
                f"HostName={self.config.vm.target_address}", "--", str(bundle),
                f"{self.config.vm.ssh_alias}:" + str(import_parent).replace("\\", "/"),
            )
        )
        if copied.returncode != 0:
            raise ColdRestoreCLIError("verified bundle transfer to exact D staging failed")
        python = remote_bundle / "operational" / "tooling" / "python" / "python.exe"
        tool = remote_bundle / "tools" / "restore" / restore_name
        audit_path = self.config.vm.root / "audit" / "events" / f"{audit_id}.json"
        marker_path = runtime_tmp / ".cold-restore-attempt.json"
        marker_b64 = base64.b64encode(marker_bytes).decode("ascii")
        materialize = (
            exact_production_root_parent_guard_script()
            + f"$root=$rootFull;$bundle={self._literal(str(remote_bundle))};"
            f"$marker={self._literal(str(marker_path))};"
            f"$expectedMarkerB64={self._literal(marker_b64)};"
            "if(-not(Test-Path -LiteralPath $marker)){throw 'transfer_attempt_marker_absent'};"
            "$markerItem=Get-Item -LiteralPath $marker -Force -ErrorAction Stop;"
            "if($markerItem.PSIsContainer-or(($markerItem.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'transfer_attempt_marker_type'};"
            "$markerStreams=@(Get-Item -LiteralPath $marker -Stream * -ErrorAction Stop);"
            "if($markerStreams.Count-ne 1-or$markerStreams[0].Stream-ne':$DATA')"
            "{throw 'transfer_attempt_marker_alternate_stream'};"
            "$actualMarkerB64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($marker));"
            "if($actualMarkerB64-ne$expectedMarkerB64){throw 'transfer_attempt_marker_differs'};"
            "function Assert-BootstrapFile{param([string]$Path,[long]$Size,[string]$Sha256);"
            "$full=[IO.Path]::GetFullPath($Path);$rootFull=[IO.Path]::GetFullPath($root).TrimEnd('\\');"
            "if(-not $full.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'bootstrap_path_escaped_exact_d'};"
            "$cursor=$full;$first=$true;$file=$null;"
            "while($true){$item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop;"
            "if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'bootstrap_reparse_chain'};"
            "if($first){if($item.PSIsContainer){throw 'bootstrap_not_regular_file'};$file=$item;$first=$false}"
            "elseif(-not $item.PSIsContainer){throw 'bootstrap_parent_not_directory'};"
            "$parent=Split-Path -Parent $cursor;if(-not $parent-or $parent-eq $cursor){break};"
            "$cursor=$parent};"
            "if($file.Length-ne $Size){throw 'bootstrap_size_mismatch'};"
            "$actual=(Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();"
            "if($actual-ne $Sha256){throw 'bootstrap_hash_mismatch'}};"
            f"Assert-BootstrapFile {self._literal(str(python))} {python_size} {self._literal(python_hash)};"
            f"Assert-BootstrapFile {self._literal(str(tool))} {tool_size} {self._literal(tool_hash)};"
            "$importChildren=@(Get-ChildItem -LiteralPath "
            f"{self._literal(str(import_parent))} -Force);"
            "if($importChildren.Count-ne 1-or-not"
            f"$importChildren[0].Name.Equals({self._literal(remote_bundle.name)},"
            "[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'transfer_import_shape_differs'};"
            f"$tmp={self._literal(str(runtime_tmp / 'work'))};"
            "New-Item -ItemType Directory -Force -Path $tmp|Out-Null;"
            "$env:PYTHONDONTWRITEBYTECODE='1';$env:TEMP=$tmp;$env:TMP=$tmp;"
            f"$lines=& {self._literal(str(python))} -I -B {self._literal(str(tool))} "
            f"--bundle-root $bundle --empty-target-root $root --staged-under-target;"
            "if($LASTEXITCODE-ne 0){throw 'bundle_materialization_failed'};"
            "$result=($lines|Select-Object -Last 1|ConvertFrom-Json);"
            "if($result.status-ne'materialized_pending_post_restore_verification'"
            "-or $result.empty_root_precondition-ne $true){throw 'materialization_identity_failed'};"
            "Remove-Item -LiteralPath $marker -Force;"
            f"Remove-Item -LiteralPath {self._literal(str(import_parent))} -Recurse -Force;"
            f"Remove-Item -LiteralPath {self._literal(str(runtime_tmp))} -Recurse -Force;"
            f"$audit={self._literal(str(audit_path))};"
            "$auditParent=Split-Path -Parent $audit;"
            "New-Item -ItemType Directory -Force -Path $auditParent|Out-Null;"
            f"$event=@{{schema_version='qrh-recovery-materialization-event/v1';event_id={self._literal(audit_id)};"
            "kind='cold_recovery_materialized';authority='evidence_only';fields=@{"
            f"bundle_id={self._literal(report.bundle_id)};release_id={self._literal(report.release_id)};"
            f"manifest_sha256={self._literal(report.release_manifest_sha256)};"
            "empty_root_precondition=$true;import_cleaned=$true;runtime_tmp_cleaned=$true}};"
            "$json=$event|ConvertTo-Json -Compress -Depth 4;"
            "[IO.File]::WriteAllText($audit,$json,(New-Object Text.UTF8Encoding($false)));"
            "$event|ConvertTo-Json -Compress -Depth 4"
        )
        result = self._ssh(materialize)
        fields = result.get("fields") if isinstance(result, dict) else None
        if (
            result != expected_event
            or
            result.get("schema_version") != "qrh-recovery-materialization-event/v1"
            or result.get("event_id") != audit_id
            or not isinstance(fields, dict)
            or fields.get("bundle_id") != report.bundle_id
            or fields.get("release_id") != report.release_id
            or fields.get("manifest_sha256") != report.release_manifest_sha256
            or any(
                fields.get(key) is not True
                for key in (
                    "empty_root_precondition", "import_cleaned", "runtime_tmp_cleaned"
                )
            )
        ):
            raise ColdRestoreCLIError(".240 recovery materialization evidence differs")
        evidence_hash = self._write_immutable_evidence(evidence_path, result)
        return {
            "status": "cold_recovery_materialized",
            "event_id": audit_id,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "evidence_sha256": evidence_hash,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--config", type=Path, required=True)
        target.add_argument("--project-root", type=Path, required=True)
        target.add_argument("--bundle-root", type=Path, required=True)

    restore = subparsers.add_parser("restore")
    common(restore)
    restore.add_argument("--evidence-output", type=Path, required=True)
    prepare = subparsers.add_parser("prepare-empty")
    common(prepare)
    prepare.add_argument("--mode", choices=("inspect", "apply"), required=True)
    prepare.add_argument("--intent-nonce", required=True)
    prepare.add_argument("--expected-legacy-deployment-id", required=True)
    prepare.add_argument("--expected-pre-delete-inventory-sha256")
    prepare.add_argument(
        "--qualification-reset-materialized",
        action="store_true",
        help=(
            "one-time reset of the exact materialized, never-activated "
            "qualification root; ordinary empty-root preparation remains unchanged"
        ),
    )
    args = parser.parse_args(argv)
    config = RuntimePublishConfig.load(args.config, expected_project_root=args.project_root)
    operator = OpenSSHColdRestore(config)
    if args.command == "restore":
        result = operator.restore(
            args.bundle_root, evidence_output=args.evidence_output
        )
    elif args.mode == "inspect":
        if args.expected_pre_delete_inventory_sha256 is not None:
            parser.error("prepare-empty inspect does not accept an expected inventory hash")
        result = operator.inspect_prepare_empty(
            args.bundle_root,
            intent_nonce=args.intent_nonce,
            expected_legacy_deployment_id=args.expected_legacy_deployment_id,
            qualification_reset_materialized=(
                args.qualification_reset_materialized
            ),
        )
    else:
        if args.expected_pre_delete_inventory_sha256 is None:
            parser.error("prepare-empty apply requires the inspected inventory hash")
        result = operator.apply_prepare_empty(
            args.bundle_root,
            intent_nonce=args.intent_nonce,
            expected_pre_delete_inventory_sha256=(
                args.expected_pre_delete_inventory_sha256
            ),
            expected_legacy_deployment_id=args.expected_legacy_deployment_id,
            qualification_reset_materialized=(
                args.qualification_reset_materialized
            ),
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
