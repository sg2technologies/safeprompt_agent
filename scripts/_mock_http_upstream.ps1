<#
.SYNOPSIS
    Internal helper — a minimal mock upstream LLM API returning a fixed,
    secret-free JSON body, standing in for https://api.openai.com so live
    validation scripts don't need a real API key.

.DESCRIPTION
    Run via Start-Process (not Start-Job) for the same reason as
    _mock_udp_collector.ps1: HttpListener.GetContext() blocks indefinitely
    once no more requests arrive, and only Stop-Process -Force (a real OS
    process kill) is guaranteed to terminate it promptly.
#>
param(
    [Parameter(Mandatory = $true)][int]$Port
)

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
    } catch {
        break
    }
    $responseBody = '{"id":"mock-1","choices":[{"message":{"role":"assistant","content":"nothing sensitive here"}}]}'
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
    $context.Response.ContentType = "application/json"
    $context.Response.ContentLength64 = $buffer.Length
    $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $context.Response.OutputStream.Close()
}
