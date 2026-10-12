<#
.SYNOPSIS
    Print the local AegisX agent enrollment status.
#>
param(
    [string]$Config = "$PSScriptRoot\..\config\agent.yaml"
)
$AgentRoot = Resolve-Path "$PSScriptRoot\.."
$VenvPy = Join-Path $AgentRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPy)) { $VenvPy = "python"; $env:PYTHONPATH = (Join-Path $AgentRoot "src") }
& $VenvPy -m aegisx_agent --status --config $Config
