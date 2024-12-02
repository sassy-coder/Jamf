 <#
.SYNOPSIS
Jamf Restricted Software Automation Script.

.DESCRIPTION
This script automates the process of analyzing applications installed across Jamf-managed devices, identifying applications
that should be restricted, and updating Jamf with newly restricted software. It also generates a log report and sends an email
summary with the details of restricted applications.

.PARAMETERS
- Mode: Determines whether the script runs in 'Testing' or 'Live' mode.
  - 'Testing': Simulates the restriction process without modifying Jamf.
  - 'Live': Restricts software in Jamf and updates the configuration.

- Whitelist: Contains applications that should not be restricted regardless of their usage count.

- Restricted Software Threshold: Applications with a usage count of 5 or less are ignored.

.FEATURES
1. Authenticates to the Jamf Pro API using Basic Authentication (Client ID and Secret support available if modified).
2. Analyzes applications in a specific device group and compares them with the whitelist and existing restricted software.
3. Adds applications not in the whitelist or already restricted, provided their usage count exceeds the threshold.
4. Sends a summary email with a log of restricted applications and attaches the CSV log file.

.VERSION
v1.0

.AUTHOR
Primary Author: P.Sassmannshausen
Co-Author: ChatGPT

.NOTES
- Ensure that the API credentials provided have the necessary permissions in Jamf Pro.
- The home directory must be scanned during inventory check-in for this script to identify all user-installed applications.
- Modify the $url, $username, and $password variables to match your Jamf instance and credentials.
- Update the $recipients array with the desired email recipients.

#>

# Define credentials for Basic Authentication
$username = "<username>"  # Replace with your Jamf API username
$password = "<password>"  # Replace with your Jamf API password
$url = "https://<server>.jamfcloud.com"  # Replace with your Jamf server URL
$Mode = "Live"

# Global variable to store the bearer token
$global:bearerToken = ""
$global:tokenExpirationEpoch = 0

# Function: Get a new bearer token (Jamf Admin username and password)
function Get-BearerToken {
    $authUrl = "$url/api/v1/auth/token"
    $authHeader = @{
        "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))
        "Accept" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $authUrl -Method POST -Headers $authHeader
        Write-Host "Raw API Response:" ($response | Out-String)
        $global:bearerToken = $response.token

        # Normalize the expiration date by removing fractional seconds
        $tokenExpiration = $response.expires -replace "\.\d+Z$", "Z"

        # Attempt to parse the normalized expiration time
        $global:tokenExpirationEpoch = ([datetime]::ParseExact($tokenExpiration, "yyyy-MM-ddTHH:mm:ssZ", $null)).ToUniversalTime().ToFileTimeUtc() / 10000000
        Write-Host "Bearer Token Acquired. Expires at epoch: $global:tokenExpirationEpoch"
    } catch {
        Write-Host "Error getting bearer token: $_"
        throw
    }
}

# Function: Ensure token validity
function Ensure-ValidToken {
    $nowEpochUTC = [datetime]::UtcNow.ToFileTimeUtc() / 10000000
    if ($global:tokenExpirationEpoch -le $nowEpochUTC) {
        Write-Host "Token expired or not available. Acquiring new token..."
        Get-BearerToken
    }
}

function Analyze-And-LogRestrictedSoftwareActions {
    param (
        [string]$jssURL,
        [hashtable]$headers,
        [int]$groupId,
        [array]$whitelist,
        [string]$Mode # Accepts 'Testing' or 'Live'
    )

    # Ensure a valid token is available
    Ensure-ValidToken

    # Create headers dynamically with the current token
    $headers = @{
        "Authorization" = "Bearer $($global:bearerToken)"
        "Accept" = "application/json"
    }

    # Fetch all restricted software
    Write-Host "Fetching all restricted software..." -ForegroundColor Cyan
    $restrictedSoftwareUrl = "$jssURL/JSSResource/restrictedsoftware"
    $restrictedResponse = Invoke-WebRequest -Uri $restrictedSoftwareUrl -Method GET -Headers $headers
    $restrictedSoftware = ($restrictedResponse.Content | ConvertFrom-Json).restricted_software
    $restrictedNames = $restrictedSoftware | ForEach-Object { $_.name }

    # Fetch all applications from the group
    Write-Host "Fetching applications from group ID $groupId..." -ForegroundColor Cyan
    $groupUrl = "$jssURL/JSSResource/computergroups/id/$groupId"
    $groupResponse = Invoke-WebRequest -Uri $groupUrl -Method GET -Headers $headers
    $groupComputers = ($groupResponse.Content | ConvertFrom-Json).computer_group.computers

    $appOccurrences = @{}

    Write-host "Warning script running in $($Mode) mode" -ForegroundColor Red

    foreach ($computer in $groupComputers) {
        try {
            Write-Host "Analyzing computer ID: $($computer.id)" -ForegroundColor Yellow
            $computerDetailResponse = Invoke-WebRequest -Uri "$jssURL/JSSResource/computers/id/$($computer.id)" -Method GET -Headers $headers
            $computerDetail = $computerDetailResponse.Content | ConvertFrom-Json
            $applications = $computerDetail.computer.software.applications

            foreach ($app in $applications) {
                $appName = $app.name

                if ($appOccurrences.ContainsKey($appName)) {
                    $appOccurrences[$appName]++
                } else {
                    $appOccurrences[$appName] = 1
                }
            }
        } catch {
            Write-Host "Error processing computer ID $($computer.id): $($_.Exception.Message)" -ForegroundColor Red
            Add-Content -Path "C:\Temp\ErrorLog.txt" -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error processing computer ID $($computer.id): $($_.Exception.Message)"
        }
    }

    # Analyze applications against restricted software and whitelist
    $log = @()
    $whitelistHash = @{}
    foreach ($app in $whitelist) { $whitelistHash[$app] = $true }

    foreach ($appName in $appOccurrences.Keys) {
        $count = $appOccurrences[$appName]

        # Skip if the count is 5 or less
        if ($count -le 5) {
            continue
        }

        if ($whitelistHash.ContainsKey($appName)) {
            $log += [PSCustomObject]@{
                Application = $appName
                Count       = $count
                Status      = "Whitelisted"
                Action      = "No Action"
            }
        } elseif ($restrictedNames -contains $appName) {
            $log += [PSCustomObject]@{
                Application = $appName
                Count       = $count
                Status      = "Already Restricted"
                Action      = "No Action"
            }
        } else {
            $log += [PSCustomObject]@{
                Application = $appName
                Count       = $count
                Status      = "Not Restricted"
                Action      = if ($Mode -eq "Live") { "Adding to Restricted Software" } else { "Would Add to Restricted Software" }
            }

            # Only add restrictions in Live mode
            if ($Mode -eq "Live") {
                try {
                    Create-RestrictedSoftware `
                        -Name "$appName" `
                        -ProcessName "$appName"
                } catch {
                    Add-Content -Path "C:\Temp\ErrorLog.txt" -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error restricting application $($appName): $($_.Exception.Message)"
                }
            }
        }
    }

    # Return log for review
    return $log
}

function Create-RestrictedSoftware {
    param (
        [string]$Name,
        [string]$ProcessName,
        [string]$MatchExactProcessName = "true",  # Use "true" or "false"
        [string]$SendNotification = "true",      # Use "true" or "false"
        [string]$KillProcess = "true",           # Use "true" or "false"
        [string]$DeleteExecutable = "true",      # Use "true" or "false"
        [string]$DisplayMessage = "",
        [string]$SiteName = "None",
        [string]$AllComputers = "false",         # Use "true" or "false"
        [int]$GroupId = 3  # Default to Group 3
    )

    # Ensure a valid token is available
    Ensure-ValidToken

    # API endpoint for creating restricted software
    $url = "https://ecwarrnambool.jamfcloud.com"
    $createUrl = "$url/JSSResource/restrictedsoftware/id/0"

    # Construct XML payload with Group 3 included in the scope
    $xmlPayload = @"
<restricted_software>
	<general>
		<name>$Name</name>
		<process_name>$ProcessName</process_name>
		<match_exact_process_name>$MatchExactProcessName</match_exact_process_name>
		<send_notification>$SendNotification</send_notification>
		<kill_process>$KillProcess</kill_process>
		<delete_executable>$DeleteExecutable</delete_executable>
		<display_message>$DisplayMessage</display_message>
		<site>
			<name>$SiteName</name>
		</site>
	</general>
	<scope>
		<all_computers>$AllComputers</all_computers>
		<computer_groups>
			<computer_group>
				<id>$GroupId</id>
				<name>All Managed Student Laptops</name>
			</computer_group>
		</computer_groups>
		<computers/>
		<buildings/>
		<departments/>
		<exclusions>
			<computers/>
			<computer_groups/>
			<buildings/>
			<departments/>
			<users/>
		</exclusions>
	</scope>
</restricted_software>
"@

    # Headers with the bearer token
    $headers = @{
        "accept" = "application/xml"
        "Authorization" = "Bearer $($global:bearerToken)"
        "Content-Type" = "application/xml"
    }

    # Debugging: Output the XML payload
    Write-Host "XML Payload Sent:" -ForegroundColor Cyan
    Write-Host $xmlPayload

    try {
        # Send POST request
        $response = Invoke-WebRequest -Uri $createUrl -Method POST -Headers $headers -Body $xmlPayload

        # Debugging: Output the response status and content
        Write-Host "Response Status: $($response.StatusCode)" -ForegroundColor Cyan
        Write-Host "Response Content: $($response.Content)" -ForegroundColor Cyan

        # Check the response
        if ($response.StatusCode -eq 201) {
            Write-Host "Restricted software record created successfully for group ID $GroupId." -ForegroundColor Green
        } else {
            Write-Host "Unexpected response status: $($response.StatusCode)" -ForegroundColor Yellow
            Add-Content -Path "C:\Temp\ErrorLog.txt" -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Unexpected response for $($Name): $($response.Content)"
        }
    } catch {
        Write-Host "Error creating restricted software record:" -ForegroundColor Red
        Write-Host $_
        Add-Content -Path "C:\Temp\ErrorLog.txt" -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error for $($Name): $($_.Exception.Message)"
    }
}

function SendMailSummary {
    param (
        [Parameter(Mandatory=$true)]
        [string]$message,

        [Parameter(Mandatory=$true)]
        [string]$logTable,  # Filtered HTML table for restricted applications

        [Parameter(Mandatory=$true)]
        [string]$fromEmail,

        [Parameter(Mandatory=$true)]
        [string[]]$toEmail,

        [Parameter(Mandatory=$true)]
        [string]$emailPassword,

        [Parameter(Mandatory=$true)]
        [string]$imageUrl,  # URL for an image to be included after the heading

        [Parameter(Mandatory=$false)]
        [string]$attachmentFilePath,  # File path for attachment

        [Parameter(Mandatory=$false)]
        [string]$smtpServer = "smtp.gmail.com",

        [Parameter(Mandatory=$false)]
        [int]$port = 587
    )

    # SMTP configuration
    $emailCredential = New-Object System.Net.NetworkCredential($fromEmail, $emailPassword)
    $smtp = New-Object Net.Mail.SmtpClient($smtpServer, $port)
    $smtp.EnableSsl = $true
    $smtp.Credentials = $emailCredential

    # Email structure
    $msg = New-Object Net.Mail.MailMessage
    $msg.From = $fromEmail
    foreach ($recipient in $toEmail) {
        $msg.To.Add($recipient)
    }

    if ($Mode -eq "Live") {
        $msg.Subject = "Jamf Restricted Software Summary"
        $h1 = "Jamf Restricted Software Summary"
        $p1 = "This email contains a summary of the newly restricted software that have a count greater than 5."
    } elseif ($Mode -eq "Testing") {
        $msg.Subject = "Jamf Restricted Software 'Simulation' Summary"
        $h1 = "Jamf Restricted Software 'Simulation' Summary"
        $p1 = "This email contains a summary of the what 'would' be restricted software with a count greater than 5 'if' the mode was set to 'Live' in the script."
    }
    $msg.IsBodyHTML = $true

    # HTML email template
    $emailContent = @"
<html>
<head>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            color: #333;
            background-color: #f4f4f4;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #eb1c22;
            text-align: center;
        }
        img {
            display: block;
            margin: 20px auto;
            max-width: 100%;
            height: auto;
        }
        h2 {
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f4f4f4;
            color: #333;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>$($h1)</h1>
        <div class="gif-container">
            <img src="https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExbTlmNngxYTFjajVpNHRlYTlpMzV5NWx4cWo4bnk0ODJsdWY5ejV6cyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9dg/BZMggpshzrPvbfQHIF/giphy.gif" alt="Summary GIF" style="max-width:100%; height:auto;">
        </div>
        <p>$($p1)</p>
        $logTable
    </div>
</body>
</html>
"@

    # Assign the content to the email body
    $msg.Body = $emailContent

    # Attach a file if provided
    if ($attachmentFilePath -and (Test-Path $attachmentFilePath)) {
        try {
            $attachment = New-Object System.Net.Mail.Attachment($attachmentFilePath)
            $msg.Attachments.Add($attachment)
            Write-Host "Attachment added: $attachmentFilePath" -ForegroundColor Green
        } catch {
            Write-Host "Error adding attachment: $_" -ForegroundColor Red
        }
    }

    # Send the email
    try {
        $smtp.Send($msg)
        Write-Host "Email sent successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error sending email: $_" -ForegroundColor Red
    }
}

# Parameters
$jssURL = "https://ecwarrnambool.jamfcloud.com" # Update with your actual Jamf URL
$groupId = 3  # Group ID for student devices

Get-BearerToken

$whitelist = @(
    "Creative Cloud Uninstaller.app",
    "Creative Cloud.app",
    "App Store.app",
    "Chess.app",
    "Google Chrome.app",
    "Launchpad.app",
    "Photo Booth.app",
    "Stickies.app",
    "Self Service.app",
    "Calculator.app",
    "Automator.app",
    "News.app",
    "Time Machine.app",
    "Console.app",
    "Maps.app",
    "Mission Control.app",
    "System Information.app",
    "Home.app",
    "Safari.app",
    "Grapher.app",
    "Bluetooth File Exchange.app",
    "Siri.app",
    "Image Capture.app",
    "TV.app",
    "Calendar.app",
    "Contacts.app",
    "Script Editor.app",
    "Disk Utility.app",
    "FaceTime.app",
    "Photos.app",
    "TextEdit.app",
    "Notes.app",
    "ColorSync Utility.app",
    "Podcasts.app",
    "Books.app",
    "Audio MIDI Setup.app",
    "AirPort Utility.app",
    "Migration Assistant.app",
    "Boot Camp Assistant.app",
    "Font Book.app",
    "Dictionary.app",
    "Terminal.app",
    "Mail.app",
    "VoiceOver Utility.app",
    "Music.app",
    "Reminders.app",
    "Screenshot.app",
    "QuickTime Player.app",
    "Messages.app",
    "FindMy.app",
    "Activity Monitor.app",
    "Digital Color Meter.app",
    "Preview.app",
    "Stocks.app",
    "VoiceMemos.app",
    "uniFLOW SmartClient.app",
    "Company Portal.app",
    "CCXProcess.app",
    "DEPNotify.app",
    "Core Sync.app",
    "Creative Cloud Helper.app",
    "Creative Cloud Installer.app",
    "Creative Cloud Desktop App.app",
    "Keychain Access.app",
    "iMovie.app",
    "zoom.us.app",
    "GarageBand.app",
    "Pages.app",
    "Keynote.app",
    "Numbers.app",
    "Install Spotify.app",
    "Shortcuts.app",
    "Clock.app",
    "Weather.app",
    "System Settings.app",
    "Spotify.app",
    "CC Troubleshooter.app",
    "minecraftpe 2.app",
    "Install Spotify 2.app",
    "minecraftpe.app",
    "Adobe Creative Cloud Diagnostics.app",
    "NAP Locked down browser.app",
    "Vivi.app",
    "System Preferences.app",
    "NAP Locked down browser Uninstaller.app",
    "Adobe Photoshop 2022.app",
    "Web Gallery.app",
    "Make Calendar.app",
    "Contact Sheets.app",
    "Adobe Illustrator.app",
    "Freeform.app",
    "TI-Nspire CX CAS Student Software.app",
    "Print Center.app",
    "Screen Sharing.app",
    "TI-Diagnostic.app",
    "Adobe Lightroom Classic.app",
    "Google Classroom Extension.app",
    "Arduino.app",
    "Autodesk Fusion 360.app",
    "Minecraft.app",
    "Adobe Photoshop 2023.app",
    "Adobe Photoshop 2024.app",
    "Audacity.app",
    "minecraftpe 3.app",
    "Adobe Media Encoder 2023.app",
    "Adobe Premiere Pro 2023.app",
    "CP210xVCPDriver.app",
    "Google Classroom Extension 2.app",
    "Wacom Display Settings.app",
    "Wacom Tablet Utility.app",
    "Microsoft Word.app",
    "Install macOS Sonoma.app",
    "Microsoft Outlook.app",
    "OneDrive.app",
    "Adobe Lightroom.app",
    "Microsoft PowerPoint.app",
    "Microsoft OneNote.app",
    "Unity Hub.app",
    "Microsoft Excel.app",
    "iPhone Mirroring.app",
    "Tips.app",
    "Passwords.app",
    "Unity.app",
    "Adobe Media Encoder 2024.app",
    "Adobe Acrobat.app",
    "Install macOS Ventura.app",
    "Install macOS Sequoia.app",
    "Blender.app",
    "VLC.app",
    "UltiMaker Cura.app",
    "Install Autodesk Fusion 360.app",
    "Google Slides.app",
    "Google Sheets.app",
    "Google Drive.app",
    "Google Docs.app",
    "KJOS IPS.app",
    "Cricut Design Space.app",
    "Adobe Premiere Pro 2024.app",
    "Wacom Desktop Center.app",
    "Wacom Center.app",
    "Visual Studio Code.app",
    "TI-Nspire CAS Student Software.App",                                                                                                 
    "TI-Nspire CX CAS Student Software 2.app",                                                                                             
    "TI-Nspire CX Student Software.app",
    "RODECaster Pro.app",
    "Python Launcher.app",
    "Adobe Acrobat Reader.app",
    "Adobe Aero.app",
    "Adobe After Effects 2022.app",
    "Adobe After Effects 2023.app",
    "Adobe After Effects 2024.app",
    "Adobe After Effects 2025.app",
    "Adobe After Effects Render Engine 2022.app",
    "Adobe After Effects Render Engine 2023.app",
    "Adobe After Effects Render Engine 2024.app",
    "Adobe After Effects Render Engine 2025.app",
    "Adobe Animate 2022.app",
    "Adobe Animate 2023.app",
    "Adobe Animate 2024.app",
    "Adobe Audition 2022.app",
    "Adobe Audition 2024.app",
    "Adobe Bridge 2023.app",
    "Adobe Bridge 2024.app",
    "Adobe Bridge 2025.app",
    "Adobe Character Animator 2022.app",
    "Adobe Character Animator 2023.app",
    "Adobe Character Animator 2024.app",
    "Adobe Digital Editions 4.5.app",
    "Adobe Dimension.app",
    "Adobe Dreamweaver 2021.app",
    "Adobe Flash Player Install Manager.app",
    "Adobe InCopy 2024.app",
    "Adobe InDesign 2022.app",
    "Adobe InDesign 2024.app",
    "Adobe Media Encoder 2022.app",
    "Adobe Media Encoder 2025.app",
    "Adobe Photoshop 2025.app",
    "Adobe Premiere Pro 2022.app",
    "Adobe Premiere Pro 2025.app",
    "Adobe Premiere Rush.app",
    "Arduino IDE.app",
    "minecraft-edu.app"
)

# Analyze applications and log results
$logResults = Analyze-And-LogRestrictedSoftwareActions -jssURL $jssURL -headers $headers -groupId $groupId -whitelist $whitelist -Mode $Mode

# Display and export log
# Generate timestamp
$now = Get-Date -Format "ddMMyyyy_HHmmss"
$logResults | Sort-Object Status, Application | Format-Table -AutoSize
$logResults | Export-Csv -Path "C:\Temp\RestrictedSoftwareAnalysis_$now.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Analysis complete. Log saved to C:\Temp\RestrictedSoftwareAnalysis.csv" -ForegroundColor Green

# Define email recipients
$recipients = @("<email1@email.com>",
                "<email2@email.com>")

# Email possible restrctions in 'Testing' mode
if ($Mode -eq "Live") {
# Filter for newly restricted applications
$restrictedApplications = $logResults | Where-Object { $_.Action -eq "Adding to Restricted Software" }
}

if ($Mode -eq "Testing") {
# Filter for 'would add to restricted applications'
$restrictedApplications = $logResults | Where-Object { $_.Action -eq "Would Add to Restricted Software" }
}

if ($restrictedApplications.Count -gt 0) {
    Write-Host "Newly restricted applications detected. Preparing to send email..." -ForegroundColor Green

    # Sort restricted applications by Count in descending order
    $restrictedApplicationsSorted = $restrictedApplications | Sort-Object -Property Count -Descending

    # Convert sorted restricted applications to an HTML table with proper styling
    $restrictedTable = $restrictedApplicationsSorted | ConvertTo-Html -Property Application, Count, Status, Action -PreContent "<h2>Newly Restricted Applications</h2>" | Out-String

    # Define the message
    $message = "The following applications were newly restricted during the latest scan."

# Find the most recent log file
$logDirectory = "C:\Temp"
$logFilePattern = "RestrictedSoftwareAnalysis_*.csv"
$latestLogFile = Get-ChildItem -Path $logDirectory -Filter $logFilePattern | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Check if a log file exists
if ($latestLogFile -ne $null) {
    $latestLogFilePath = $latestLogFile.FullName
    Write-Host "Latest log file found: $latestLogFilePath" -ForegroundColor Green

    # Call the email function
    SendMailSummary `
        -message $message `
        -logTable $restrictedTable `
        -fromEmail "<emailaddresshere>" `
        -toEmail $recipients `
        -emailPassword "<password>" `
        -imageUrl "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.shutterstock.com%2Fsearch%2Frestriction&psig=AOvVaw3cRY6uHS5hLDJBWgJj0KuF&ust=1733140609787000&source=images&cd=vfe&opi=89978449&ved=0CBEQjRxqFwoTCLjs9YbChooDFQAAAAAdAAAAABAE" `
   -attachmentFilePath $latestLogFilePath
} else {
    Write-Host "No log file found in $logDirectory matching the pattern $logFilePattern" -ForegroundColor Red
}
} else {
    Write-Host "No newly restricted applications. Email will not be sent." -ForegroundColor Yellow
}
