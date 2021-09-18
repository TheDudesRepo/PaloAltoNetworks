#If you have many firewalls in Panorama this script grabs that list of firewalls and backs up the device state.
#Palo Alto Device State Backups are a must because it includes all configurations to include the certificates. 
#Then this script can email you the status of the backups as a good check. 

#Trusts certificate errors
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#Forces TLS 1.2 Connection
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Decrypts the API Key
$EndDate = get-date -UFormat "%Y-%m-%d %H:%M:%S"
$Encrypted = Get-Content "C:\SomeFolder\EncryptedAPI.txt"
$Secure = ConvertTo-SecureString -String $Encrypted
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#Below is the procedure to get the API Key from Panorama or Gateway. All of these commands can be run from Powershell/Windows/Core 
# PS curl -k -X GET 'https://<firewall>/api/?type=keygen&user=<username>&password=<password>'  (curl works best in powershell core)
# PS C:\> $Secure = Read-Host -AsSecureString
# PS C:\> $Secure
# System.Security.SecureString  (this just means it worked)
# PS C:\> $Encrypted = ConvertFrom-SecureString -SecureString $Secure
# PS C:\> $Encrypted | clip (saves the encrypted text to your clipboard)
# Then save this to a file and in this example it would be C:\SomeFolder\EncryptedAPI.txt

#Gets the list of firewalls from panorama
$req = Invoke-WebRequest "https://IP-Address-Of-Panorama/api/?type=op&cmd=<show><devices><connected></connected></devices></show>&key=$PlainPassword"
$req.Content | Select-Xml -XPath '/*/*/*/*' | select -ExpandProperty Node | select hostname | Out-File "C:\backups\Firewalls.txt"
$firewalls = gc "C:\backups\Firewalls.txt"  | foreach-object {$_ -replace "hostname", ""} | foreach-object {$_ -replace "--------", ""} | foreach {$_.TrimEnd()} | where {$_ -ne ""}

#Loops through the list of firewalls it got from panorama and backs up the device state
foreach ($gw in $firewalls) {wget https://$gw/api/?type=export"&"category=device-state"&"key=$PlainPassword -OutFile ('D:\backups\gateways\{0}--{1}.tgz' -f $gw, ($EndDate.ToString() -replace ':','')  -replace '\s','')}

#Emails How the Backup Went
$PublicIP = (Invoke-WebRequest -uri "https://api.ipify.org/").Content
$PublicIPinfo = Invoke-RestMethod -Uri ('https://ipinfo.io/') | ConvertTo-Html -Head $style
$From = "MyEmail@gmail.com"
$Subject = "Palo Device State Backup Check from $PublicIP"
$Body = "Palo Alto Firewall Device State Backup Checks"
$Body1 = "-------------------------------------------"
$Body2 = "Just a Backup Check <br> $PublicIPinfo"
$BodyA = Get-ChildItem "D:\Backups\gateways" | Sort-Object -Property LastWriteTime
$BodyAll = ($Body,$Body1,$Body2,$BodyA | Format-Table -AutoSize)
$password = Get-Content "C:\SomeFolder\Password.txt" | ConvertTo-SecureString 
$Credential = New-Object System.Management.Automation.PsCredential("MyEmail@gmail.com",$password)
$SMTPServer = "smtp.gmail.com"
$SMTPPort = "587"
$To = "SomeEmail@domain.com"

Send-MailMessage -From $From -to $To -Subject $Subject -Body ($BodyAll | Out-String) -SmtpServer $SMTPServer -port $SMTPPort -Credential $Credential

#Moves Backups into archive
$Path1 = "D:\Backups\gateways"
$ArchivePath = "D:\Backups\gateways\Archives"
$Daysback ="-1"
$CurrentDate = Get-Date
$DatetoMove = $CurrentDate.AddDays($Daysback)
Get-ChildItem $Path1 | Where-Object {$_.LastWriteTime -lt $DatetoMove} | Move-Item -Destination $ArchivePath
