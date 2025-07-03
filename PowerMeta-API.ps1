<#
By Beau Bullock (@dafthack)
.SYNOPSIS
    PowerMeta-API - Find files hosted on target domains using Google Custom Search API

.DESCRIPTION
    This script uses Google's Custom Search API to find publicly available files (PDF, DOCX, XLSX, etc.)
    hosted on a target domain. It's more reliable than web scraping and doesn't trigger anti-bot measures.

.PARAMETER TargetDomain
    The target domain to search for files (e.g., "example.com")

.PARAMETER ApiKey
    Your Google Custom Search API key

.PARAMETER SearchEngineId
    Your Google Custom Search Engine ID

.PARAMETER FileTypes
    Comma-separated list of file extensions to search for
    Default: "pdf,docx,xlsx,doc,xls,pptx,ppt"

.PARAMETER MaxResults
    Maximum number of results to return per file type (default: 100)

.PARAMETER OutputFile
    Optional file to save the results to

.PARAMETER OutputDir
    Optional directory to save downloaded files

.PARAMETER Download
    Switch to enable downloading files

.PARAMETER Extract
    Switch to enable extracting metadata from files

.PARAMETER ExtractAllToCsv
    Optional file to save extracted metadata to

.PARAMETER UserAgent
    Optional User-Agent string for downloading files

.PARAMETER ShowUrls
    Switch to enable verbose output showing URLs returned by API

.EXAMPLE
    .\PowerMeta-API.ps1 -TargetDomain "example.com" -ApiKey "YOUR_API_KEY" -SearchEngineId "YOUR_SEARCH_ENGINE_ID"

.EXAMPLE
    .\PowerMeta-API.ps1 -TargetDomain "example.com" -FileTypes "pdf,xlsx" -MaxResults 50 -OutputFile "results.txt"

.EXAMPLE
    .\PowerMeta-API.ps1 -TargetDomain "example.com" -ApiKey "YOUR_API_KEY" -SearchEngineId "YOUR_SEARCH_ENGINE_ID" -Download -OutputDir "downloads"

.EXAMPLE
    .\PowerMeta-API.ps1 -TargetDomain "example.com" -ApiKey "YOUR_API_KEY" -SearchEngineId "YOUR_SEARCH_ENGINE_ID" -Download -Extract -OutputDir "downloads"

.EXAMPLE
    .\PowerMeta-API.ps1 -TargetDomain "example.com" -ApiKey "YOUR_API_KEY" -SearchEngineId "YOUR_SEARCH_ENGINE_ID" -Download -Extract -ExtractAllToCsv "metadata.csv" -OutputDir "downloads"

.NOTES
    Setup Instructions:
    1. Go to https://console.cloud.google.com/
    2. Create a new project or select existing one
    3. Enable the "Custom Search API"
    4. Create credentials (API Key)
    5. Go to https://programmablesearchengine.google.com/
    6. Create a new search engine
    7. Set search engine to search the entire web
    8. Get your Search Engine ID
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TargetDomain,
    
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$ApiKey,
    
    [Parameter(Mandatory = $true, Position = 2)]
    [string]$SearchEngineId,
    
    [Parameter(Mandatory = $false)]
    [string]$FileTypes = "pdf,docx,xlsx,doc,xls,pptx,ppt",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxResults = 100,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$Download,
    
    [Parameter(Mandatory = $false)]
    [switch]$Extract,
    
    [Parameter(Mandatory = $false)]
    [string]$ExtractAllToCsv = "",
    
    [Parameter(Mandatory = $false)]
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowUrls
)

# Add System.Web assembly for URL encoding
Add-Type -AssemblyName System.Web

# Function to search for files using Google Custom Search API
function Search-FilesOnDomain {
    param(
        [string]$Domain,
        [string]$FileType,
        [string]$ApiKey,
        [string]$SearchEngineId,
        [int]$MaxResults
    )
    
    try {
        Write-Host "[*] Searching for $FileType files on $Domain..."
        
        $results = @()
        $startIndex = 1
        
        # Google Custom Search API allows max 10 results per request, so we need to paginate
        while ($results.Count -lt $MaxResults) {
            $query = "site:$Domain filetype:$FileType"
            $encodedQuery = [System.Web.HttpUtility]::UrlEncode($query)
            
            $apiUrl = "https://www.googleapis.com/customsearch/v1?key=$ApiKey&cx=$SearchEngineId&q=$encodedQuery&start=$startIndex"
            
            Write-Host "  [*] Requesting results $startIndex to $($startIndex + 9)..."
            
            $response = Invoke-RestMethod -Uri $apiUrl -Method Get -TimeoutSec 30
            
            if ($response.items) {
                $batchCount = 0
                if ($ShowUrls) {
                    Write-Host "  [*] Debug: URLs returned by API:"
                }
                foreach ($item in $response.items) {
                    if ($ShowUrls) {
                        Write-Host "    $($item.link)"
                    }
                    # Accept all results from the API since filetype: parameter should already filter correctly
                    $results += $item.link
                    $batchCount++
                    if ($ShowUrls) {
                        Write-Host "      ✓ Added to results"
                    }
                }
                Write-Host "  [*] Found $($response.items.Count) results in this batch, $batchCount added to results"
            } else {
                Write-Host "  [*] No more results found"
                break
            }
            
            $startIndex += 10
            
            # Add small delay between API requests
            Start-Sleep -Milliseconds 500
        }
        
        Write-Host "[*] Total $FileType files found: $($results.Count)"
        return $results
    }
    catch {
        Write-Host "[!] Error searching for $FileType files: $($_.Exception.Message)"
        return @()
    }
}

# Function to validate API credentials
function Test-APICredentials {
    param(
        [string]$ApiKey,
        [string]$SearchEngineId
    )
    
    try {
        Write-Host "[*] Testing API credentials..."
        $testQuery = [System.Web.HttpUtility]::UrlEncode("test")
        $testUrl = "https://www.googleapis.com/customsearch/v1?key=$ApiKey&cx=$SearchEngineId&q=$testQuery&num=1"
        
        $response = Invoke-RestMethod -Uri $testUrl -Method Get -TimeoutSec 10
        
        if ($response.searchInformation) {
            Write-Host "[+] API credentials are valid!"
            return $true
        } else {
            Write-Host "[!] API response format unexpected"
            return $false
        }
    }
    catch {
        Write-Host "[!] API credentials test failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to download files from URLs
function Download-Files {
    param(
        [array]$FileUrls,
        [string]$OutputDir,
        [string]$UserAgent
    )
    
    Write-Host "[*] Downloading $($FileUrls.Count) files now."
    
    # Create output directory if it doesn't exist
    if (!(Test-Path $OutputDir)) {
        Write-Host "[*] Creating output directory: $OutputDir"
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    $OutputPath = Convert-Path $OutputDir
    
    # Disable SSL certificate validation for downloads
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    
    $counter = 1
    foreach ($url in $FileUrls) {
        try {
            $filename = Split-Path $url -Leaf
            $filepath = Join-Path $OutputPath $filename
            
            # Handle duplicate filenames
            if (Test-Path $filepath) {
                $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($filename)
                $ext = [System.IO.Path]::GetExtension($filename)
                $filename = "$nameWithoutExt-$counter$ext"
                $filepath = Join-Path $OutputPath $filename
                $counter++
            }
            
            Write-Host "[*] Downloading: $url"
            Invoke-WebRequest -Uri $url -UserAgent $UserAgent -UseBasicParsing -OutFile $filepath -TimeoutSec 30
            Write-Host "[+] Saved: $filename"
        }
        catch {
            Write-Host "[!] Failed to download $url : $($_.Exception.Message)"
        }
    }
    
    Write-Host "[*] Download complete. Files saved to: $OutputPath"
}

# Function to extract metadata using exiftool
function Extract-Metadata {
    param(
        [string]$OutputDir,
        [string]$ExtractAllToCsv = ""
    )
    
    if (!(Test-Path $OutputDir)) {
        Write-Host "[!] Output directory $OutputDir does not exist! Canceling metadata extraction."
        return
    }
    
    $OutputPath = Convert-Path $OutputDir
    
    try {
        $exiftool = Get-ChildItem "exiftool.exe" -ErrorAction Stop
        $exifpath = $exiftool.FullName
    }
    catch {
        Write-Host "[!] Exiftool.exe was not found in the current directory!"
        Write-Host "[!] Please download exiftool from https://exiftool.org/ and place it in the same directory as this script."
        return
    }
    
    if ($ExtractAllToCsv -ne "") {
        # Extract all metadata to CSV
        Write-Host "[*] Extracting all metadata from $OutputDir to $ExtractAllToCsv"
        $cmd = "& `"$exifpath`" `"$OutputPath`" -CSV > `"$ExtractAllToCsv`""
        Invoke-Expression $cmd
        Write-Host "[+] All metadata saved to: $ExtractAllToCsv"
    }
    else {
        # Extract only Author and Creator metadata
        Write-Host "[*] Extracting Author and Creator metadata from $OutputDir"
        $filearray = Get-ChildItem $OutputPath
        $output = @()
        
        foreach ($file in $filearray) {
            $filepath = Join-Path $OutputPath $file.Name
            Write-Host "[*] Extracting metadata from: $($file.Name)"
            
            $cmd = "& `"$exifpath`" `"$filepath`" -CSV -Author -Creator"
            $exifout = Invoke-Expression $cmd | Out-String
            $strippedout = $exifout -replace "SourceFile" -replace "Author" -replace "Creator" -replace "`n" -replace "`r"
            $output += $strippedout -replace "^.*$($file.Name),"
        }
        
        $allmeta = @()
        $allmeta += $output -split ","
        $uniquemeta = $allmeta | Where-Object { $_ -ne "" } | Sort-Object -Unique
        
        Write-Host ""
        Write-Host "[*] Extracted 'Author' and 'Creator' metadata:"
        Write-Host "----------------------------------------"
        if ($uniquemeta.Count -gt 0) {
            foreach ($meta in $uniquemeta) {
                Write-Host $meta
            }
        } else {
            Write-Host "No Author/Creator metadata found."
        }
        Write-Host ""
    }
}

# Main execution
Write-Host "=========================================="
Write-Host "PowerMeta-API - Google Custom Search Tool"
Write-Host "=========================================="
Write-Host ""

# Validate API credentials
if (-not (Test-APICredentials -ApiKey $ApiKey -SearchEngineId $SearchEngineId)) {
    Write-Host "[!] Invalid API credentials. Please check your API key and Search Engine ID."
    Write-Host "[!] See the script header for setup instructions."
    exit 1
}

# Parse file types
$fileTypeArray = $FileTypes -split "," | ForEach-Object { $_.Trim() }

Write-Host "[*] Target Domain: $TargetDomain"
Write-Host "[*] File Types: $($fileTypeArray -join ', ')"
Write-Host "[*] Max Results per type: $MaxResults"
Write-Host ""

# Search for each file type
$allResults = @()

foreach ($fileType in $fileTypeArray) {
    $results = Search-FilesOnDomain -Domain $TargetDomain -FileType $fileType -ApiKey $ApiKey -SearchEngineId $SearchEngineId -MaxResults $MaxResults
    $allResults += $results
    Write-Host ""
}

# Remove duplicates and sort
$uniqueResults = $allResults | Sort-Object -Unique

Write-Host "=========================================="
Write-Host "SEARCH COMPLETE"
Write-Host "=========================================="
Write-Host "[*] Total unique files found: $($uniqueResults.Count)"
Write-Host ""

# Display results
if ($uniqueResults.Count -gt 0) {
    Write-Host "Files found:"
    Write-Host "------------"
    foreach ($result in $uniqueResults) {
        Write-Host $result
    }
    
    # Save to file if specified
    if ($OutputFile -ne "") {
        try {
            $uniqueResults | Out-File -FilePath $OutputFile -Encoding UTF8
            Write-Host ""
            Write-Host "[+] Results saved to: $OutputFile"
        }
        catch {
            Write-Host "[!] Error saving to file: $($_.Exception.Message)"
        }
    }
    
    # Handle download functionality
    if ($Download) {
        if ($OutputDir -eq "") {
            $OutputDir = Get-Date -Format "yyyy-MM-dd-HHmmss"
        }
        Download-Files -FileUrls $uniqueResults -OutputDir $OutputDir -UserAgent $UserAgent
    }
    elseif ($Download -eq $false) {
        $title = "Download Files?"
        $message = "Would you like to download all of the files discovered?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Downloads all of the target files."
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "The files will not be downloaded."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

        switch ($result) {
            0 {
                if ($OutputDir -eq "") {
                    $OutputDir = Get-Date -Format "yyyy-MM-dd-HHmmss"
                }
                Write-Host "[*] Now downloading the files."
                Download-Files -FileUrls $uniqueResults -OutputDir $OutputDir -UserAgent $UserAgent
            }
            1 { Write-Host "[*] No files will be downloaded." }
        }
    }
    
    # Handle metadata extraction
    if ($Extract) {
        if ($OutputDir -eq "") {
            Write-Host "[!] No output directory specified for metadata extraction. Skipping."
        } else {
            Write-Host "[*] Now extracting metadata from the files."
            if ($ExtractAllToCsv -ne "") {
                Extract-Metadata -OutputDir $OutputDir -ExtractAllToCsv $ExtractAllToCsv
            } else {
                Extract-Metadata -OutputDir $OutputDir
            }
        }
    }
    elseif ($Extract -eq $false -and $OutputDir -ne "") {
        $title = "Extract Metadata?"
        $message = "Would you like to extract metadata from all of the files downloaded now?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Extracts metadata from downloaded files."
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No metadata will be extracted at this time."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

        switch ($result) {
            0 {
                Write-Host "[*] Now extracting metadata from the files."
                if ($ExtractAllToCsv -ne "") {
                    Extract-Metadata -OutputDir $OutputDir -ExtractAllToCsv $ExtractAllToCsv
                } else {
                    Extract-Metadata -OutputDir $OutputDir
                }
            }
            1 { 
                Write-Host "[*] No metadata will be extracted at this time."
                Write-Host "[*] If you wish to extract metadata later, you can run:"
                Write-Host "    Extract-Metadata -OutputDir `"$OutputDir`""
            }
        }
    }
} else {
    Write-Host "[*] No files found for the specified criteria."
}

