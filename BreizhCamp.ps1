# Déclarer une variable
$a = "BreizhCamp"
[int]$a = "BreizhCamp"
[int]$a = 1

# Accéder à l'aide d'un cmdlet
Get-Help Get-Member

# Le pipeLine
$a | Get-Member

# Normalisation
Get-Verb

# valider l'existence d'un fichier/dossier 
Test-Path C:\PowerShell

# Créer un partage 
New-SmbShare -Name "Partage" -Path C:\PowerShell -Description "Test Shared Folder" -FullAccess fabien -ChangeAccess bob -ReadAccess Everyone
#Get-SmbShare
# Remove-SMBShare

# Lister un répertoire
Get-ChildItem C:\PowerShell -Recurse # ls

# marche aussi pour les certificats
ls cert:\ -recurse | select -first 10

# Autres PSDrive disponibles
Get-PSDrive

# Lister les process
Get-Process
Get-Process | Where Name -like "*a*"
(Get-Process).where({$_.Name -like "*a*"})

# Kill a process
Start-Process notepad
Get-Process | ForEach-Object {If ($_.ProcessName -eq "notepad") {$_.Kill()}}

# Lister les services
Get-Service
Get-Service | Out-GridView
Get-Service | Sort-Object Name | ConvertTo-Html | Out-File C:\PowerShell\output.html
ii C:\PowerShell\output.html


# Télécharger le contenu d'un site
wget "http://channel9.msdn.com/Feeds/RSS"

# Mesurer la durée d'exécution
Measure-Command {Invoke-RestMethod -Uri  "http://channel9.msdn.com/Feeds/RSS"}

# Interrogation des classes WMI
Get-CimInstance -ClassName Win32_ComputerSystem | Select *

# Scheduler une tâche planifiée
$Trigger = New-JobTrigger -Daily -At 3am
Register-ScheduledJob -Name DailyBackup -Trigger $trigger -ScriptBlock {Copy-Item C:\PowerShell C:\Backup$((Get-Date).ToFileTime()) -Recurse -Force -PassThru}

# Pinger un serveur 
Test-Connection localhost

# Et en mieux 
Test-NetConnection -CommonTCPPort WinRM -ComputerName localhost

# Récupérer le contenu d'un fichier
Get-Content C:\PowerShell\text.txt 
Get-content C:\PowerShell\text.txt -wait # attente d'�critures dans le fichier

# Réaliser un teaming
$networkCards = Get-NetAdapter -Physical
New-NetLbfoTeam -Name 'teamTest' -TeamNicName 'Teamed Card' -TeamMembers $NetworkCards.Name -TeamingMode Lacp -LoadBalancingAlgorithm IPAddresses -Confirm:$false

# Lister les ressources disponibles
Get-DscResource | Format-wide -Property Name -Column 3

# Monter la syntaxe d'une ressource
Get-DscResource -Name file -Syntax

# Création des fichiers MOF
configuration BreizhCamp {

    param (
        [String[]]$Server=$env:computerName
    )

    Node $Server {

        File SetupFile {

            Ensure          = "present"
            SourcePath      = "C:\PowerShell\DesiredStateConfiguration\SomeSetup.exe"
            DestinationPath = "C:\PowerShell"
            Type            = "File"

        }
    }
}

Push-Location C:\PowerShell
BreizhCamp
#BreizhCamp -server "PC01","PC02","PC03","BREIZH01"

# Vérification de la présence des fichiers
Get-ChildItem C:\PowerShell\BreizhCamp

# Execution de la configuration
Start-DscConfiguration -Path C:\PowerShell\BreizhCamp -verbose

# Tester la configuration d'un serveur
Test-DSCConfiguration -verbose

# Trouver toutes les versions de Putty disponibles
Find-Package -AllVersions -Name putty

# Forcer l'installation sans confirmation à partir de la source chocolatey
Add-PackageSource -Name chocolatey -Location http://chocolatey.org/api/v2 -Provider chocolatey -Trusted -Verbose

# Installation de la version 0.61
Find-Package -RequiredVersion 0.61 -Name putty | Install-Package -Verbose

# lister les packages installés sur le pc
Get-Package

# Désinstaller Putty 0.61
Get-Package | ? Version -eq '0.61' | Uninstall-Package -verbose

# Lister les évenements du jour
Get-EventLog -LogName application -After ((date)+-1d)  | out-gridview

# remplir un AD en 10s :)
gc C:\PowerShell\users.csv
Import-Csv C:\PowerShell\users.csv -Delimiter ";" -Header "samaccountname","name","givenname" | ForEach {
    $props = @{
        Name = $_.samaccountname
        SamAccountName = $_.samAccountName
        GivenName = $_.givenname
        UserPrincipalName = $_.samaccountname + "@Breizh.rox"
        Surname = $_.name
        DisplayName = $($_.name + " " + $_.givenname).ToLower()
        Description = "Compte utilisateur pour demo BreizhCamp"
    }
    New-ADUser @props
}


# Charger une librairie
Add-Type -LiteralPath C:\PowerShell\Binaries\Renci.SshNet.dll

# Cr�er un objet .NET
$Client = New-Object Renci.SshNet.SshClient("***.***.***.***",22,"user","P4ssw0rd")
$Client | Get-Member

#Ex�cuter une m�thode
$Client.Connect()

#Ex�cuter une commande sur un serveur Linux
$Client.RunCommand("uname -a").Result

$Client.Disconnect()
$Client.Dispose()