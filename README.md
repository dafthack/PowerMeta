# PowerMeta
PowerMeta searches for publicly available files hosted on various websites for a particular domain by using specially crafted Google, and Bing searches. It then allows for the download of those files from the target domain. After retrieving the files, the metadata associated with them can be analyzed by PowerMeta. Some interesting things commonly found in metadata are usernames, domains, software titles, and computer names.

## Public File Discovery
For many organizations it's common to find publicly available files posted on their external websites. Many times these files contain sensitive information that might be of benefit to an attacker like usernames, domains, software titles or computer names. PowerMeta searches both Bing and Google for files on a particular domain using search strings like "site:targetdomain.com filetype:pdf". By default it searches for "pdf, docx, xlsx, doc, xls, pptx, and ppt". 

## Metadata Extraction
PowerMeta uses Exiftool by Phil Harvey to extract metadata information from files. If you would prefer to download the binary from his site directly instead of using the one in this repo it can be found here: http://www.sno.phy.queensu.ca/~phil/exiftool/. Just make sure the exiftool executable is in the same directory as PowerMeta.ps1 when it is run. By default it just extracts the 'Author' and 'Creator' fields as these commonly have usernames saved. However all metadata for files can be extracted by passing PowerMeta the -ExtractAllToCsv flag.

## Requirements
PowerShell version 3.0 or later

## Usage

### Google API
Google's anti-bot protections are super aggressive now making it almost impossible to scrape results directly so you may get mixed results using PowerMeta.ps1. To get around this the easiest solution is to just use Google's API. I added a new script here called "PowerMeta-API.ps1" that does just that.

Here's step-by-step instructions:

Step 1: Create Google Cloud Project
- Go to Google Cloud Console (https://cloud.google.com/)
- Login with a Google account
- Click "Select a project" → "New Project"
- Enter a project name (e.g., "PowerMeta-API")
- Click "Create"

Step 2: Enable Custom Search API
- In your project, go to "APIs & Services" → "Library"
- Search for "Custom Search API"
- Click on it and press "Enable"

Step 3: Create API Key
- Go to "APIs & Services" → "Credentials"
- Click "Create Credentials" → "API Key"
- Copy your API key (you'll need this)

Step 4: Create Custom Search Engine
- Go to Google Programmable Search Engine (https://programmablesearchengine.google.com)
- Click "Add a search engine"
- Enter any name (e.g., "PowerMeta Search")
- For "Sites to search", select "Search the entire web"
- Click "Create"
- Copy your Search Engine ID (looks like: 94e6b2cd62344413c)

Run it with:
``` PowerShell
.\PowerMeta-API.ps1 -TargetDomain "targetdomain.com" -ApiKey "<API key>" -SearchEngineId "<search engine ID>" -ExtractAllToCsv allmetadata.csv
```

## Non-API PowerMeta Instructions

### Import the Module
```
C:\> powershell.exe -exec bypass
PS C:\> Import-Module PowerMeta.ps1
```
### Basic Search
This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, docx, xlsx, doc, xls, pptx, or pptx. Once it has finished crafting this list it will prompt the user asking if they wish to download the files from the target domain. After downloading files it will prompt again for extraction of metadata from those files.
``` PowerShell
PS C:\> Invoke-PowerMeta -TargetDomain targetdomain.com
```
### Changing FileTypes and Automatic Download and Extract
This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, or xml. It will then automatically download them from the target domain and extract metadata.
``` PowerShell
PS C:\> Invoke-PowerMeta -TargetDomain targetdomain.com -FileTypes "pdf, xml" -Download -Extract
```
### Downloading Files From A List
This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, docx, xlsx, doc, xls, pptx, or pptx and write the links of files found to disk in a file called "target-domain-links.txt".
``` PowerShell
PS C:\> Invoke-PowerMeta -TargetDomain targetdomain.com -TargetFileList target-domain-links.txt
```
### Extract All Metadata and Limit Page Search
This command will initiate Google and Bing searches for files on the 'targetdomain.com' domain ending with a file extension of pdf, docx, xlsx, doc, xls, pptx, or pptx but only search the first two pages. All metadata (not just the default fields) will be saved in a CSV called all-target-metadata.csv.
``` PowerShell
PS C:\> Invoke-PowerMeta -TargetDomain targetdomain.com -MaxSearchPages 2 -ExtractAllToCsv all-target-metadata.csv
```
### Extract Metadata From Files In A Directory
This command will simply extract all the metadata from all the files in the folder "\2017-03-031-144953\" and save it in a CSV called all-target-metadata.csv
``` PowerShell
PS C:\> ExtractMetadata -OutputDir .\2017-03-031-144953\ -ExtractAllToCsv all-target-metadata.csv
```
## PowerMeta Options
```
TargetDomain        - The target domain to search for files. 
FileTypes           - A comma seperated list of file extensions to search for. By default PowerMeta searches for "pdf, docx, xlsx, doc, xls, pptx, ppt".
OutputList          - A file to output the list of links discovered through web searching to. 
OutputDir           - A directory to store all downloaded files in.
TargetFileList      - List of file links to download.
Download            - Instead of being prompted interactively pass this flag to auto-download files found.
Extract             - Instead of being prompted interactively pass this flag to extract metadata from found files pass this flag to auto-extract any metadata.
ExtractAllToCsv     - All metadata (not just the default fields) will be extracted from files to a CSV specified with this flag.
UserAgent           - Change the default User Agent used by PowerMeta.
MaxSearchPages      - The maximum number of pages to search on each search engine.
```
