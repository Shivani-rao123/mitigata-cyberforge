$taskRoot = $PSScriptRoot
foreach ($site in @(@{Name='studio';Port=3000},@{Name='planner';Port=3001})) {
  if (-not (Get-NetTCPConnection -State Listen -LocalPort $site.Port -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath (Get-Command node).Source -ArgumentList @('server.cjs', $site.Name, $site.Port) -WorkingDirectory $taskRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskRoot "$($site.Name).log") -RedirectStandardError (Join-Path $taskRoot "$($site.Name).error.log")
  }
}
