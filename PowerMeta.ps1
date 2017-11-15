# Disable cert checks
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

Function Invoke-PowerMeta{

    <#
    .SYNOPSIS
    This function searches for publicly available files hosted on various sites for a particular domain by using specially crafted Google, and Bing searches. It then allows for the download of those files from the target domain. After retrieving the files, the metadata associated with them can be analyzed by PowerMeta. Some interesting things commonly found in metadata are usernames, domains, software titles, and computer names.

    PowerMeta Function: Invoke-PowerMeta
    Author: Beau Bullock (@dafthack)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION
    This function searches for publicly available files hosted on various sites for a particular domain by using specially crafted Google, and Bing searches. It then allows for the download of those files from the target domain. After retrieving the files, the metadata associated with them can be analyzed by PowerMeta. Some interesting things commonly found in metadata are usernames, domains, software titles, and computer names.
    
    .PARAMETER TargetDomain
    The target domain to search for files. 

    .PARAMETER FileTypes
    A comma seperated list of file extensions to search for. By default PowerMeta searches for "pdf, docx, xlsx, doc, xls, pptx, ppt".

    .PARAMETER OutputList
    A file to output the list of links discovered through web searching to. 

    .PARAMETER OutputDir
    A directory to store all downloaded files in.

    .PARAMETER TargetFileList
    List of file links to download.
    
    .PARAMETER Download
    Instead of being prompted interactively pass this flag to auto-download files found.

    .PARAMETER Extract
    Instead of being prompted interactively pass this flag to extract metadata from found files pass this flag to auto-extract any metadata.

    .PARAMETER ExtractAllToCsv
    All metadata (not just the default fields) will be extracted from files to a CSV specified with this flag.

    .PARAMETER UserAgent
    Change the default User Agent used by PowerMeta.

    .PARAMETER MaxSearchPages
    The maximum number of pages to search on each search engine.

    .Example
    
    C:\PS> Invoke-PowerMeta -TargetDomain targetdomain.com
    Description
    -----------
    This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, docx, xlsx, doc, xls, pptx, or pptx. Once it has finished crafting this list it will prompt the user asking if they wish to download the files from the target domain. After downloading files it will prompt again for extraction of metadata from those files.

    .Example
    
    C:\PS> Invoke-PowerMeta -TargetDomain targetdomain.com -FileTypes "pdf, xml" -Download -Extract
    Description
    -----------
    This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, or xml. It will then automatically download them from the target domain and extract metadata.

    .Example

    C:\PS> Invoke-PowerMeta -TargetDomain targetdomain.com -TargetFileList target-domain-links.txt
    Description
    -----------
    This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, docx, xlsx, doc, xls, pptx, or pptx and write the links of files found to disk in a file called "target-domain-links.txt".

    .Example

    C:\PS> Invoke-PowerMeta -TargetDomain targetdomain.com -MaxSearchPages 2 -ExtractAllToCsv all-target-metadata.csv
    Description
    -----------
    This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, docx, xlsx, doc, xls, pptx, or pptx but only search the first to pages. All metadata (not just the default fields) will be saved in a CSV called all-target-metadata.csv.
    
    .Example

    C:\PS> ExtractMetadata -OutputDir .\2017-03-031-144953\ -ExtractAllToCsv all-target-metadata.csv
    Description
    -----------
    This command will simply extract all the metadata from all the files in the folder "\2017-03-031-144953\" and save it in a CSV called all-target-metadata.csv

    #>

      Param
      (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $TargetDomain = "",

        [Parameter(Position = 1, Mandatory = $false)]
        [string]
        $FileTypes = "pdf, docx, xlsx, doc, xls, pptx, ppt",

        [Parameter(Position = 2, Mandatory = $false)]
        [string]
        $OutputList = "",

        [Parameter(Position = 3, Mandatory = $false)]
        [string]
        $OutputDir = "",

        [Parameter(Position = 4, Mandatory = $false)]
        [string]
        $TargetFileList = "",

        [Parameter(Position = 5, Mandatory = $false)]
        [switch]
        $Download,

        [Parameter(Position = 6, Mandatory = $false)]
        [switch]
        $Extract,

        [Parameter(Position = 7, Mandatory = $false)]
        [string]
        $ExtractAllToCsv = "",

        [Parameter(Position = 8, Mandatory = $false)]
        [string]
        $UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        
        [Parameter(Position = 9, Mandatory = $false)]
        [int]
        $MaxSearchPages = 5

        )

    #If no target file list was provided we will perform searches and craft one.
    If ($TargetFileList -eq "")
        {

            $filetypearray = @()
            $filetypearray = $FileTypes -split ", "

            $validlinks = @()
            foreach ($filetype in $filetypearray)
                {
            
                #Performing a Google search first

                Write-Output "[*] Searching Google for 'site:$TargetDomain filetype:$filetype'"
                $googlesearch = "https://www.google.com/search?q=site:$TargetDomain+filetype:$filetype&num=100"
                $pagelinks = @()
                $pagelinks = (Invoke-WebRequest -Uri $googlesearch -UserAgent $UserAgent -UseBasicParsing).Links
                $hrefs = @()
                $hrefs = $pagelinks.href
    
                #Adding each valid url from page 1 to a list of valid links
                Write-Output "[*] Now Analyzing page 1 of Google search results (100 results per page)"
                foreach($url in $hrefs){
                    if (($url -like "*$TargetDomain*") -and ($url -like "*.$filetype*"))
                        {
                        if ($url -like "*http://*")
                            {
                            $strippedurl = [regex]::match($url,"http([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        elseif ($url -like "*https://*")
                            {
                            $strippedurl = [regex]::match($url,"https([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        }
         
                    }
                #Determining if there are more than one page
                $otherpages = @()
                $otherpageslimit = @()
                foreach($url in $hrefs)
                    {
                    if ($url -like "*search?q*start=*")
                        {
                        $otherpages += "https://www.google.com$url" + "&num=100"
                        }

                    }
                
                $otherpages = $otherpages | sort | unique
                $pagecount = $otherpages.count
                if ($pagecount -gt $MaxSearchPages)
                    {
                        $totalpagelimit = $MaxSearchPages - 1
                        for($j=0; $j -lt $totalpagelimit; $j++)
                        {                                    
                            $otherpageslimit += $otherpages[$j]
                        }
                    }

                $otherpageslimit = $otherpageslimit -replace "&amp;","&"
                $morepagelinks = @()
                $morehrefs = @()
                $i = 2
                #for each additional page in the Google search results find links
                foreach($page in $otherpageslimit)
                    {
                    Write-Output "[*] Now Analyzing page $i of Google search results (100 results per page)"
                    $i++
                    $morepagelinks = (Invoke-WebRequest -Uri $page -UserAgent $UserAgent -UseBasicParsing).Links
                    $morehrefs = $morepagelinks.href
                    foreach($url in $morehrefs){
                    if (($url -like "*$TargetDomain*") -and ($url -like "*.$filetype*"))
                        {
                        if ($url -like "*http://*")
                            {
                            $strippedurl = [regex]::match($url,"http([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        elseif ($url -like "*https://*")
                            {
                            $strippedurl = [regex]::match($url,"https([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        }
         
                    }
                    }

                #Performing a Bing search second

                Write-Output "[*] Searching Bing for 'site:$TargetDomain filetype:$filetype'"
                $bingsearch = "http://www.bing.com/search?q=site:$TargetDomain%20filetype:$filetype&count=30"
                $bingpagelinks = @()
                $bingpagelinks = (Invoke-WebRequest -Uri $bingsearch -UserAgent $UserAgent -UseBasicParsing).Links
                $binghrefs = @()
                $binghrefs = $bingpagelinks.href
            
                #Adding each valid link from page 1 to an array
                Write-Output "[*] Now Analyzing page 1 of Bing search results (30 results per page)"
                foreach($url in $binghrefs){
                    if (($url -like "*$TargetDomain*") -and ($url -like "*.$filetype*"))
                        {
                        if ($url -like "*http://*")
                            {
                            $strippedurl = [regex]::match($url,"http([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        elseif ($url -like "*https://*")
                            {
                            $strippedurl = [regex]::match($url,"https([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        }
                    }
                $bingotherpages = @()
                
                #Determining if there are more pages to search
                foreach($url in $binghrefs)
                    {
                    if ($url -like "*search?q*first=*")
                        {
                        $bingotherpages += "https://www.bing.com$url" + "&count=30"
                        }

                    }
                $bingotherpages = $bingotherpages | sort | unique
                $bingotherpages = $bingotherpages -replace "&amp;","&"
                $morepagelinks = @()
                $morehrefs = @()
                $i = 2

                #for each additional page in the Bing search results find links
                foreach($page in $bingotherpages)
                    {
                    Write-Output "[*] Now Analyzing page $i of Bing search results (30 results per page)"
                    $i++
                    $morepagelinks = (Invoke-WebRequest -Uri $page -UserAgent $UserAgent -UseBasicParsing).Links
                    $morehrefs = $morepagelinks.href
                    foreach($url in $morehrefs){
                    if (($url -like "*$TargetDomain*") -and ($url -like "*.$filetype*"))
                        {
                        if ($url -like "*http://*")
                            {
                            $strippedurl = [regex]::match($url,"http([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        elseif ($url -like "*https://*")
                            {
                            $strippedurl = [regex]::match($url,"https([^\)]+).$filetype").Value
                            $validlinks += $strippedurl
                            }
                        }
         
                    }
                    }
           
         
                }

                $targetlinks = @()
                #getting rid of webcache links
                foreach ($link in $validlinks)
                    {
                    if ($link -notlike "*webcache.google*")
                        {
                        $targetlinks += $link
                        }
                    }
                $targetlinks = $targetlinks | sort | unique

                Write-Output ('[*] A total of ' + $targetlinks.count + ' files were discovered.')
                Write-Output "`n"

                #If an OutputList is specified write the results to disk
                If ($OutputList -ne "")
                    {
                    Write-Output "[*] Writing links to a file at $OutputList"
                    $targetlinks | Out-File -Encoding ascii $OutputList
                    }

        }
    #If a target list was specified let's use that.
    If ($TargetFileList -ne "")

        {
        $targetlinks = Get-Content $TargetFileList
        Write-Output "[*]Using the file list at $TargetFileList"
        Write-Output ('[*] A total of ' + $targetlinks.count + ' files were found.')
        }
    # If no output directory was named we will create one in with the current date/time.
        If($OutputDir -eq "")
            {
                $OutputDir = Get-Date -format yyyy-MM-dd-HHmmss
            }
    If ($Download)
    {
        Get-TargetFiles -targetlinks $targetlinks -OutputDir $OutputDir -UserAgent $UserAgent
    }
    elseif($Download -eq $false)
        {
            $title = "Download Files?"
            $message = "Would you like to download all of the files discovered?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Downloads all of the target files."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "The files will not be downloaded."

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

            switch ($result)
                {
                 0 {
                    "[*] Now downloading the files."
                    Get-TargetFiles -targetlinks $targetlinks -OutputDir $OutputDir -UserAgent $UserAgent
                   }
                 1 {"[*] No files will be downloaded."}
                }

        }
    If ($Extract)
        {
            Write-Output "[*] Now extracting metadata from the files."
            If ($ExtractAllToCsv -ne "")
            {
                ExtractMetadata -OutputDir $OutputDir -ExtractAllToCsv $ExtractAllToCsv
            }
            else{
                ExtractMetadata -OutputDir $OutputDir
            }
        }
    elseif($Extract -eq $false)
        {
            $title = "Extract Metadata?"
            $message = "Would you like to extract metadata from all of the files downloaded now?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Extracts metadata from downloaded files."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No metadata will be extracted at this time."

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

            switch ($result)
                {
                 0 {
                    Write-Output "[*] Now extracting metadata from the files."
                    If ($ExtractAllToCsv)
                    {
                        ExtractMetadata -OutputDir $OutputDir -ExtractAllToCsv
                    }
                    else{
                        ExtractMetadata -OutputDir $OutputDir
                    }
                   }
                 1 {"[*] No metadata will be extracted at this time. If you wish to extract metadata later you can run the ExtractMetadata function on a directory of files like so: PS C:>ExtractMetadata -OutputDir `"C:\Users\username\directory-of-files\`""}
                }
        }
}
#Function to download files from a webserver
Function Get-TargetFiles{
        Param(
        
        [Parameter(Position = 0, Mandatory = $false)]
        [array]
        $targetlinks = "",

        [Parameter(Position = 1, Mandatory = $false)]
        [string]
        $OutputDir = "",

        [Parameter(Position = 2, Mandatory = $false)]
        [string]
        $UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

        )
        
        Write-Output ('[*] Downloading ' + $targetlinks.count + ' files now.')


        # Testing to see if the output directory exists. If not, we'll create it.
        $TestOutputDir = Test-Path $OutputDir
        If($TestOutputDir -ne $True)
            {
                Write-Output "[*] The output directory $OutputDir does not exist. Creating directory $OutputDir."
                mkdir $OutputDir
            }

    # Getting the full path of the output dir.
    $OutputPath = Convert-Path $OutputDir
    #If the Download flag was set don't bother asking about downloading
          ## Choose to ignore any SSL Warning issues caused by Self Signed Certificates      
          ## Code From http://poshcode.org/624

          ## Create a compilation environment
          $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
          $Compiler=$Provider.CreateCompiler()
          $Params=New-Object System.CodeDom.Compiler.CompilerParameters
          $Params.GenerateExecutable=$False
          $Params.GenerateInMemory=$True
          $Params.IncludeDebugInformation=$False
          $Params.ReferencedAssemblies.Add("System.DLL") > $null

$TASource=@'
  namespace Local.ToolkitExtensions.Net.CertificatePolicy {
    public class TrustAll : System.Net.ICertificatePolicy {
      public TrustAll() { 
      }
      public bool CheckValidationResult(System.Net.ServicePoint sp,
        System.Security.Cryptography.X509Certificates.X509Certificate cert, 
        System.Net.WebRequest req, int problem) {
        return true;
      }
    }
  }
'@ 
          $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
          $TAAssembly=$TAResults.CompiledAssembly

          ## We now create an instance of the TrustAll and attach it to the ServicePointManager
          $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
          [System.Net.ServicePointManager]::CertificatePolicy=$TrustAll
  
          ## end code from http://poshcode.org/624

          
          $k = 1
          foreach ($link in $targetlinks){
         
          $filename = $link -replace "^.*\/"
          $testpath = ($OutputDir + "\" + $filename)
          if (!(Test-Path $testpath)) 
          {
          Write-Output "Now Downloading $link"
          Invoke-WebRequest $link -UserAgent $UserAgent -UseBasicParsing -OutFile ($OutputPath + "\" + $(Split-Path $link -Leaf))
          }
          Else{
          #When downloading files if a file has the same name a number is prepended
          Write-Output "Now Downloading $link"
          Invoke-WebRequest $link -UserAgent $UserAgent -UseBasicParsing -OutFile ($OutputPath + "\" + $k + $(Split-Path $link -Leaf))

          }
          $k++
          }

}

#Use exiftool to extract metadata from each file
Function ExtractMetadata{
        Param(

        [Parameter(Position = 0, Mandatory = $false)]
        [string]
        $OutputDir = "",

        [Parameter(Position = 1, Mandatory = $false)]
        [string]
        $ExtractAllToCsv = ""
        )
        #If "ExtractAllToCsv flag is set extract all metadata from files
        if ($ExtractAllToCsv -ne "")
        {
            $exifout = @()
            if (!(Test-Path $OutputDir))
                {
                Write-Output "[*] $OutputDir does not exist! Canceling metadata extraction."
                break
                }
            else{
                $OutputPath = Convert-Path $OutputDir
                Write-Output "[*] Now extracting metadata from $OutputDir"
                try{
                $exiftool = Get-ChildItem "exiftool.exe" -ErrorAction Stop
                
                $exifpath = $exiftool.FullName | Out-String
                $exifpath = $exifpath -replace "`n" -replace "`r"
                $cmd = $exifpath + " " + $OutputPath + " -CSV > $ExtractAllToCsv"
                Invoke-Expression $cmd
                }
                catch
                {
                Write-Output "[*] Exiftool.exe was not found in the current directory! Exiting."
                }
                

            }
        }
        else{
            #If we are not extracting all Metadata just get the Author and Creator for possible usernames.
                if (!(Test-Path $OutputDir))
                {
                Write-Output "[*] $OutputDir does not exist! Canceling metadata extraction."
                break
                }
                else{
                $OutputPath = Convert-Path $OutputDir
                $filearray = Get-ChildItem $OutputPath
                $output = @()
                try{
                $exiftool = Get-ChildItem "exiftool.exe" -ErrorAction Stop
                $exifpath = $exiftool.FullName | Out-String
                $exifpath = $exifpath -replace "`n" -replace "`r"
                ForEach ($file in $filearray) {
                $filepath = $OutputPath + "\" + $file
                Write-Output "[*] Now extracting metadata from $filepath"
                

                $cmd = $exifpath + " " + $filepath + " -CSV -Author -Creator" 
                $exifout = Invoke-Expression $cmd | Out-String
                $strippedout = $exifout -replace "SourceFile" -replace "Author" -replace "Creator" -replace "`n" -replace "`r"
                $modpath = $OutputPath -replace "\\", "\/"
                $output += $strippedout -replace "^.*$file,"
                }
                $allmeta = @()
                $allmeta += $output -split ","
                $uniquemeta = $allmeta | sort | unique

                Write-Output "`n[*] Extracted 'Author' and 'Creator' metadata"
                $uniquemeta
                Write-Output "`n"
                }
                catch
                {
                Write-Output "[*] Exiftool.exe was not found in the current directory! Exiting."                
                }

                }
            }
}
