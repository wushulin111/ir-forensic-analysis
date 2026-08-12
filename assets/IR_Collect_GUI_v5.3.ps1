# ============================================================
# IR 应急取证采集 v5.3 - 图形化选择启动器
# 自动布局 + 高分屏适配 + 滚动内容区
# 选择采集方式后调用内嵌的 IR_Collect_v5.3.ps1
# ============================================================

Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction Stop
[System.Windows.Forms.Application]::EnableVisualStyles()

trap {
    $errLine = $_.InvocationInfo.ScriptLineNumber
    try { [System.Windows.Forms.MessageBox]::Show("错误: $($_.Exception.Message)`n行: $errLine", "IR取证 - 错误", "OK", "Error") | Out-Null } catch {}
    exit 1
}

$primary  = [System.Drawing.Color]::FromArgb(31, 78, 121)
$accent   = [System.Drawing.Color]::FromArgb(0, 120, 212)
$descGray = [System.Drawing.Color]::FromArgb(100, 100, 100)
$headerBg = [System.Drawing.Color]::FromArgb(238, 246, 252)
$bodyBg   = [System.Drawing.Color]::FromArgb(250, 251, 253)
$bottomBg = [System.Drawing.Color]::FromArgb(246, 247, 249)
$white    = [System.Drawing.Color]::White
$darkText = [System.Drawing.Color]::FromArgb(40, 40, 40)

function New-WrapLabel {
    param(
        [string]$Text,
        [System.Drawing.Color]$ForeColor = $descGray,
        [float]$FontSize = 9.5
    )
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text
    $lbl.AutoSize = $true
    $lbl.MaximumSize = New-Object System.Drawing.Size(760, 0)
    $lbl.Margin = New-Object System.Windows.Forms.Padding(4, 0, 4, 6)
    $lbl.ForeColor = $ForeColor
    $lbl.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", $FontSize)
    return $lbl
}

function New-ContentTable {
    $tlp = New-Object System.Windows.Forms.TableLayoutPanel
    $tlp.ColumnCount = 1
    $tlp.RowCount = 0
    $tlp.Dock = [System.Windows.Forms.DockStyle]::Fill
    $tlp.AutoSize = $true
    $tlp.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $tlp.Padding = New-Object System.Windows.Forms.Padding(16, 12, 16, 14)
    $tlp.Margin = New-Object System.Windows.Forms.Padding(0)
    $colStyle = New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)
    $tlp.ColumnStyles.Add($colStyle) | Out-Null
    return $tlp
}

function Add-AutoRow {
    param(
        [System.Windows.Forms.TableLayoutPanel]$Panel,
        [System.Windows.Forms.Control]$Control
    )
    $Panel.RowCount += 1
    $rowStyle = New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)
    $Panel.RowStyles.Add($rowStyle) | Out-Null
    $Panel.Controls.Add($Control)
    $Panel.SetRow($Control, ($Panel.RowCount - 1))
    $Panel.SetColumn($Control, 0)
}

function New-SectionBox {
    param([string]$Title)
    $gb = New-Object System.Windows.Forms.GroupBox
    $gb.Text = $Title
    $gb.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 11, [System.Drawing.FontStyle]::Bold)
    $gb.ForeColor = $primary
    $gb.BackColor = $white
    $gb.Dock = [System.Windows.Forms.DockStyle]::Fill
    $gb.AutoSize = $true
    $gb.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $gb.Padding = New-Object System.Windows.Forms.Padding(14, 10, 14, 14)
    $gb.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 22)
    return $gb
}

function New-ModeRadio {
    param([string]$Text)
    $rb = New-Object System.Windows.Forms.RadioButton
    $rb.Text = $Text
    $rb.AutoSize = $true
    $rb.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 11, [System.Drawing.FontStyle]::Bold)
    $rb.ForeColor = $darkText
    $rb.Margin = New-Object System.Windows.Forms.Padding(4, 12, 4, 4)
    return $rb
}

function New-OptionCheckBox {
    param([string]$Text)
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $Text
    $chk.AutoSize = $true
    $chk.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 10.5)
    $chk.ForeColor = $darkText
    $chk.Margin = New-Object System.Windows.Forms.Padding(4, 12, 4, 4)
    return $chk
}

function New-IRCollectForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "IR 应急取证采集 v5.3.3"
    $form.ClientSize = New-Object System.Drawing.Size(1000, 920)
    $form.MinimumSize = New-Object System.Drawing.Size(900, 820)
    $form.MaximumSize = New-Object System.Drawing.Size(1400, 1200)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.BackColor = $bodyBg
    $form.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 9)
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font

    # ---------- Header ----------
    $header = New-Object System.Windows.Forms.TableLayoutPanel
    $header.Dock = [System.Windows.Forms.DockStyle]::Fill
    $header.ColumnCount = 1
    $header.RowCount = 2
    $header.AutoSize = $true
    $header.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $header.Padding = New-Object System.Windows.Forms.Padding(40, 22, 40, 16)
    $header.BackColor = $headerBg
    $header.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $header.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $header.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $title = New-Object System.Windows.Forms.Label
    $title.Text = "IR 应急取证采集 v5.3.3"
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 18, [System.Drawing.FontStyle]::Bold)
    $title.ForeColor = $primary
    $title.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)

    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = "按现场需求选择采集内容：常规快照适合快速取证，深度取证证据更完整但耗时更长。"
    $subtitle.AutoSize = $true
    $subtitle.MaximumSize = New-Object System.Drawing.Size(780, 0)
    $subtitle.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 10)
    $subtitle.ForeColor = $descGray

    $header.Controls.Add($title)
    $header.SetRow($title, 0)
    $header.SetColumn($title, 0)
    $header.Controls.Add($subtitle)
    $header.SetRow($subtitle, 1)
    $header.SetColumn($subtitle, 0)

    # ---------- Scrollable content ----------
    $content = New-Object System.Windows.Forms.Panel
    $content.Dock = [System.Windows.Forms.DockStyle]::Fill
    $content.AutoScroll = $true
    $content.BackColor = $bodyBg

    $mainTlp = New-Object System.Windows.Forms.TableLayoutPanel
    $mainTlp.AutoSize = $true
    $mainTlp.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $mainTlp.Dock = [System.Windows.Forms.DockStyle]::Top
    $mainTlp.ColumnCount = 1
    $mainTlp.RowCount = 0
    $mainTlp.Padding = New-Object System.Windows.Forms.Padding(40, 20, 40, 28)
    $mainTlp.Margin = New-Object System.Windows.Forms.Padding(0)
    $mainCol = New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)
    $mainTlp.ColumnStyles.Add($mainCol) | Out-Null

    # ---------- 一、采集模式 ----------
    $modeBox = New-SectionBox -Title "一、采集模式"
    $modeTlp = New-ContentTable

    $rbQuick = New-ModeRadio -Text "常规快照（推荐）"
    $rbQuick.Checked = $true
    Add-AutoRow $modeTlp $rbQuick

    $lblQuick = New-WrapLabel -Text "采集进程、网络、账号、持久化、系统信息、事件日志、浏览器记录，约 2-5 分钟，适合绝大多数现场。"
    Add-AutoRow $modeTlp $lblQuick

    $rbDeep = New-ModeRadio -Text "深度取证"
    Add-AutoRow $modeTlp $rbDeep

    $lblDeep = New-WrapLabel -Text "追加 Amcache、Shimcache、Prefetch、SRUM 等离线痕迹与扩展日志，证据更完整，耗时明显增加，建议重点终端或有明确入侵线索时使用。"
    Add-AutoRow $modeTlp $lblDeep

    $modeBox.Controls.Add($modeTlp)
    Add-AutoRow $mainTlp $modeBox

    # ---------- 二、可选采集项 ----------
    $optBox = New-SectionBox -Title "二、可选采集项"
    $optTlp = New-ContentTable

    $chkSensitive = New-OptionCheckBox -Text "采集敏感数据（-IncludeSensitive）"
    Add-AutoRow $optTlp $chkSensitive

    $lblSensitive = New-WrapLabel -Text "包含 SAM/SYSTEM/SECURITY/SOFTWARE 配置单元与浏览器凭据库；仅获得授权且确需取证时勾选。"
    Add-AutoRow $optTlp $lblSensitive

    $chkSkip = New-OptionCheckBox -Text "跳过文件系统扫描（-SkipFileScan）"
    Add-AutoRow $optTlp $chkSkip

    $lblSkip = New-WrapLabel -Text "跳过勒索扩展名、勒索信、威胁文件及下载目录扫描；适合大磁盘和现场时间紧张，文件侧证据覆盖会减少。"
    Add-AutoRow $optTlp $lblSkip

    $chkSystem = New-OptionCheckBox -Text "扫描系统目录（-IncludeSystemDirs）"
    Add-AutoRow $optTlp $chkSystem

    $lblSystem = New-WrapLabel -Text "追加扫描 Windows\Temp、ProgramData、Program Files，排查系统级持久化与可疑载荷，耗时明显增加。"
    Add-AutoRow $optTlp $lblSystem

    $depthRow = New-Object System.Windows.Forms.TableLayoutPanel
    $depthRow.AutoSize = $true
    $depthRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $depthRow.ColumnCount = 3
    $depthRow.RowCount = 1
    $depthRow.Margin = New-Object System.Windows.Forms.Padding(4, 14, 4, 6)
    $depthRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $depthRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $depthRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $lblDepth = New-Object System.Windows.Forms.Label
    $lblDepth.Text = "扫描深度（-ScanDepth）："
    $lblDepth.AutoSize = $true
    $lblDepth.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 10)
    $lblDepth.ForeColor = $darkText
    $lblDepth.Margin = New-Object System.Windows.Forms.Padding(4, 4, 8, 4)

    $numDepth = New-Object System.Windows.Forms.NumericUpDown
    $numDepth.Minimum = 1
    $numDepth.Maximum = 8
    $numDepth.Value = 5
    $numDepth.Width = 72
    $numDepth.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 10)
    $numDepth.Margin = New-Object System.Windows.Forms.Padding(4, 4, 10, 4)

    $lblDepthDesc = New-WrapLabel -Text "1-8，默认 5；数值越大越深、耗时越长。"

    $depthRow.Controls.Add($lblDepth)
    $depthRow.SetRow($lblDepth, 0)
    $depthRow.SetColumn($lblDepth, 0)
    $depthRow.Controls.Add($numDepth)
    $depthRow.SetRow($numDepth, 0)
    $depthRow.SetColumn($numDepth, 1)
    $depthRow.Controls.Add($lblDepthDesc)
    $depthRow.SetRow($lblDepthDesc, 0)
    $depthRow.SetColumn($lblDepthDesc, 2)
    Add-AutoRow $optTlp $depthRow

    $optBox.Controls.Add($optTlp)
    Add-AutoRow $mainTlp $optBox

    # ---------- 三、定向采集 ----------
    $targetBox = New-SectionBox -Title "三、定向采集"
    $targetTlp = New-ContentTable

    $targetRow = New-Object System.Windows.Forms.TableLayoutPanel
    $targetRow.AutoSize = $true
    $targetRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $targetRow.ColumnCount = 2
    $targetRow.RowCount = 1
    $targetRow.Margin = New-Object System.Windows.Forms.Padding(4, 4, 4, 2)
    $targetRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $targetRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $lblTarget = New-Object System.Windows.Forms.Label
    $lblTarget.Text = "定向目标（-Target）："
    $lblTarget.AutoSize = $true
    $lblTarget.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 9.5)
    $lblTarget.ForeColor = $darkText
    $lblTarget.Margin = New-Object System.Windows.Forms.Padding(4, 5, 8, 4)

    $txtTarget = New-Object System.Windows.Forms.TextBox
    $txtTarget.Width = 360
    $txtTarget.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 10)
    $txtTarget.Margin = New-Object System.Windows.Forms.Padding(4, 2, 4, 4)

    $targetRow.Controls.Add($lblTarget)
    $targetRow.SetRow($lblTarget, 0)
    $targetRow.SetColumn($lblTarget, 0)
    $targetRow.Controls.Add($txtTarget)
    $targetRow.SetRow($txtTarget, 0)
    $targetRow.SetColumn($txtTarget, 1)
    Add-AutoRow $targetTlp $targetRow

    $lblTargetDesc = New-WrapLabel -Text "可选。补充指定软件的进程、服务、注册表、计划任务与文件痕迹；内置 tailscale，其他名称按关键词匹配。可留空跳过。"
    Add-AutoRow $targetTlp $lblTargetDesc

    $targetBox.Controls.Add($targetTlp)
    Add-AutoRow $mainTlp $targetBox

    $content.Controls.Add($mainTlp)

    # ---------- Bottom bar ----------
    $bottom = New-Object System.Windows.Forms.TableLayoutPanel
    $bottom.Dock = [System.Windows.Forms.DockStyle]::Fill
    $bottom.ColumnCount = 3
    $bottom.RowCount = 2
    $bottom.AutoSize = $true
    $bottom.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $bottom.Padding = New-Object System.Windows.Forms.Padding(40, 14, 40, 18)
    $bottom.BackColor = $bottomBg
    $bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $bottom.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $bottom.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $lblInfo = New-WrapLabel -Text "点击[开始采集]后会弹出 UAC 提权确认；完成后生成 C:\IR\IR_主机名_时间戳.zip。"
    $bottom.Controls.Add($lblInfo)
    $bottom.SetRow($lblInfo, 0)
    $bottom.SetColumn($lblInfo, 0)
    $bottom.SetColumnSpan($lblInfo, 3)

    $lblVer = New-Object System.Windows.Forms.Label
    $lblVer.Text = "版本 v5.3.3 · 自动提权 · 离线采集"
    $lblVer.AutoSize = $true
    $lblVer.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 9.5)
    $lblVer.ForeColor = $descGray
    $lblVer.Margin = New-Object System.Windows.Forms.Padding(4, 10, 8, 0)
    $bottom.Controls.Add($lblVer)
    $bottom.SetRow($lblVer, 1)
    $bottom.SetColumn($lblVer, 0)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "退出"
    $btnExit.Width = 120
    $btnExit.Height = 48
    $btnExit.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 10.5)
    $btnExit.ForeColor = $darkText
    $btnExit.BackColor = $bottomBg
    $btnExit.FlatStyle = "Flat"
    $btnExit.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(200, 205, 212)
    $btnExit.Margin = New-Object System.Windows.Forms.Padding(8, 8, 8, 0)
    $btnExit.Dock = [System.Windows.Forms.DockStyle]::Fill

    $btnStart = New-Object System.Windows.Forms.Button
    $btnStart.Text = "开始采集"
    $btnStart.Width = 160
    $btnStart.Height = 48
    $btnStart.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 11, [System.Drawing.FontStyle]::Bold)
    $btnStart.ForeColor = $white
    $btnStart.BackColor = $accent
    $btnStart.FlatStyle = "Flat"
    $btnStart.FlatAppearance.BorderSize = 0
    $btnStart.Margin = New-Object System.Windows.Forms.Padding(8, 8, 0, 0)
    $btnStart.Dock = [System.Windows.Forms.DockStyle]::Fill

    $bottom.Controls.Add($btnExit)
    $bottom.SetRow($btnExit, 1)
    $bottom.SetColumn($btnExit, 1)
    $bottom.Controls.Add($btnStart)
    $bottom.SetRow($btnStart, 1)
    $bottom.SetColumn($btnStart, 2)

    # ---------- Root layout ----------
    $root = New-Object System.Windows.Forms.TableLayoutPanel
    $root.Dock = [System.Windows.Forms.DockStyle]::Fill
    $root.ColumnCount = 1
    $root.RowCount = 3
    $root.Margin = New-Object System.Windows.Forms.Padding(0)
    $root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $root.Controls.Add($header)
    $root.SetRow($header, 0)
    $root.SetColumn($header, 0)
    $root.Controls.Add($content)
    $root.SetRow($content, 1)
    $root.SetColumn($content, 0)
    $root.Controls.Add($bottom)
    $root.SetRow($bottom, 2)
    $root.SetColumn($bottom, 0)

    $form.Controls.Add($root)

    # ---------- Events ----------
    $btnExit.Add_Click({
        $form.Close()
    })

    $btnStart.Add_Click({
        try {
            $argsList = New-Object System.Collections.Generic.List[string]
            if ($rbDeep.Checked) { $argsList.Add("-DeepForensic") }
            if ($chkSensitive.Checked) { $argsList.Add("-IncludeSensitive") }
            if ($chkSkip.Checked) { $argsList.Add("-SkipFileScan") }
            if ($chkSystem.Checked) { $argsList.Add("-IncludeSystemDirs") }
            $argsList.Add("-ScanDepth")
            $argsList.Add([string][int]$numDepth.Value)
            $targetName = if ($null -ne $txtTarget) { ([string]$txtTarget.Text).Trim() } else { '' }
            if ($targetName) {
                $argsList.Add("-Target")
                $argsList.Add($targetName)
            }

            $scriptPath = Join-Path $env:TEMP "IR_Collect_v5.3.ps1"
            if (-not (Test-Path -LiteralPath $scriptPath)) {
                [System.Windows.Forms.MessageBox]::Show("未找到内嵌采集脚本，请重新下载 exe。", "错误", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                return
            }

            $psArgs = New-Object System.Collections.Generic.List[string]
            $psArgs.Add("-NoProfile")
            $psArgs.Add("-ExecutionPolicy")
            $psArgs.Add("Bypass")
            $psArgs.Add("-File")
            $psArgs.Add($scriptPath)
            foreach ($a in $argsList) { $psArgs.Add($a) }

            $form.Hide()
            try {
                $p = Start-Process -FilePath "powershell.exe" -ArgumentList $psArgs.ToArray() -Wait -PassThru
                if ($p.ExitCode -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show("采集流程已完成，请查看 C:\IR 下的压缩包。", "完成", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                } else {
                    [System.Windows.Forms.MessageBox]::Show("采集流程已结束，返回码：$($p.ExitCode)，请查看 C:\IR 下的 collection.log。", "完成", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("启动采集脚本失败：$($_.Exception.Message)", "错误", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        } catch {
            $em = "错误: $($_.Exception.Message)`n行: $($_.InvocationInfo.ScriptLineNumber)"
            [System.Windows.Forms.MessageBox]::Show($em, "IR取证 - 错误", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        } finally {
            $form.Close()
        }
    })

    $form.AcceptButton = $btnStart
    $form.CancelButton = $btnExit
    return $form
}

$form = New-IRCollectForm
[System.Windows.Forms.Application]::Run($form)
