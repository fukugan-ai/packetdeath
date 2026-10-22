# packetdeath 常駐 SetTcpEntry ブリッジ。
#
# 標準入力から `la,lp,ra,rp`（10進の u32。packetdeath 側で network byte
# order へ変換済み）を1行ずつ受け取り、`SetTcpEntry`（iphlpapi.dll）で
# 該当 TCP 接続を切って `rc=<n> us=<f>` を1行ずつ返す。
#
# この C# 定義は `unsafe` キーワードを
# 使わない（`[DllImport]` は P/Invoke であり C# の `unsafe` とは別物）。
#
# 標準入力が閉じたら（packetdeath 側 process の終了）ループを抜けて終了する。
# 不正な入力（4つ組でない・uint32 に変換できない）は `rc=-1` を返して
# 常駐そのものは落とさない。

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PacketDeathTcpKill
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [DllImport("iphlpapi.dll")]
    public static extern uint SetTcpEntry(ref MIB_TCPROW row);
}
"@

# MIB_TCP_STATE_DELETE_TCB。この状態を書き込むと該当 TCP 接続を切る。
$DeleteTcbState = 12

while ($true) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line) {
        break
    }

    $parts = $line.Split(',')
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($parts.Length -ne 4) {
            throw "expected 4 fields, got $($parts.Length)"
        }
        $row = New-Object PacketDeathTcpKill+MIB_TCPROW
        $row.dwState = $DeleteTcbState
        $row.dwLocalAddr = [uint32]$parts[0]
        $row.dwLocalPort = [uint32]$parts[1]
        $row.dwRemoteAddr = [uint32]$parts[2]
        $row.dwRemotePort = [uint32]$parts[3]
        $rc = [PacketDeathTcpKill]::SetTcpEntry([ref]$row)
    } catch {
        $rc = -1
    }
    $sw.Stop()
    $us = $sw.Elapsed.TotalMilliseconds * 1000

    [Console]::Out.WriteLine("rc=$rc us=$us")
    [Console]::Out.Flush()
}
