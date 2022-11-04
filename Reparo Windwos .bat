@ECHO OFF 
:: NOME   : Reparo completo do Windows  
:: AUTOR  : Ivo Dias 
:: VERSAO : Enterprise Release Slim 
title Reparo completo do Windows 
color 2 
DISM.exe /Online /Cleanup-image /Scanhealth 
Dism.exe /Online /Cleanup-Image /CheckHealth 
Dism.exe /Online /Cleanup-Image /SpSuperseded 
Dism.exe /Online /Cleanup-Image /startComponentCleanup 
DISM.exe /Online /Cleanup-image /Restorehealth 
sfc /scannow 
chkdsk /r /f 
net stop bits 
net stop wuauserv 
net stop appidsvc 
net stop cryptsvc 
Del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" 
Del c:\windows\SoftwareDistribution /f 
sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU) 
sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU) 
cd /d %windir%\system32 
esentutl /d %windir%\softwaredistribution\datastore\datastore.edb 
reg&nbsp;delete&nbsp;"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"&nbsp;/f&nbsp; 
reg&nbsp;delete&nbsp;"HKLM\COMPONENTS\PendingXmlIdentifier"&nbsp;/f&nbsp; 
reg&nbsp;delete&nbsp;"HKLM\COMPONENTS\NextQueueEntryIndex"&nbsp;/f&nbsp; 
reg&nbsp;delete&nbsp;"HKLM\COMPONENTS\AdvancedInstallersNeedResolving"&nbsp;/f&nbsp; 
del %TEMP%\*.* /s /f /q  
call :print Protegendo o computador contra Softwares ilicitos . . . 
taskkill /f /im KMSPico.exe /t 
taskkill /f /im AutoKMS.exe /t 
if exist "%ProgramFiles%\KMSpico" ( 
    takeown /f "%ProgramFiles%\KMSpico" 
    attrib -r -s -h /s /d "%ProgramFiles%\KMSpico" 
    rmdir /s /q "%ProgramFiles%\KMSpico" 
) else if exist "C:\Windows\AutoKMS" ( 
    takeown /f "C:\Windows\AutoKMS" 
    attrib -r -s -h /s /d "C:\Windows\AutoKMS" 
    rmdir /s /q "C:\Windows\AutoKMS" 
) 
if exist "C:\Windows\KMSPico" ( 
    takeown /f "C:\Windows\KMSPico" 
    attrib -r -s -h /s /d "C:\Windows\KMSPico" 
    rmdir /s /q "C:\Windows\KMSPico" 
) else if exist "C:\Windows\System32\Tasks\AutoKMS" ( 
    takeown /f "C:\Windows\System32\Tasks\AutoKMS" 
    attrib -r -s -h /s /d "C:\Windows\System32\Tasks\AutoKMS" 
    rmdir /s /q "C:\Windows\System32\Tasks\AutoKMS" 
) 
ipconfig /release 
ipconfig /renew 
ipconfig /flushdns 
Netsh winsock reset 
nbtstat -rr  
net localgroup administradores localservice /add 
fsutil resource setautoreset true C:\ 
netsh int ip reset resetlog.txt &nbsp; 
netsh winsock reset all 
netsh int 6to4 reset all 
Netsh int ip reset all 
netsh int ipv4 reset all 
netsh int ipv6 reset all 
netsh int httpstunnel reset all 
netsh int isatap reset all 
netsh int portproxy reset all 
netsh int tcp reset all 
netsh int teredo reset all 
sc config wuauserv start= auto 
sc config bits start= auto 
sc config DcomLaunch start =auto 
set&nbsp;key=HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX&nbsp; 
call&nbsp;:addReg&nbsp;"%key%"&nbsp;"IsConvergedUpdateStackEnabled"&nbsp;"REG_DWORD"&nbsp;"0"&nbsp; 
set&nbsp;key=HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings&nbsp; 
call&nbsp;:addReg&nbsp;"%key%"&nbsp;"UxOption"&nbsp;"REG_DWORD"&nbsp;"0"&nbsp; 
set&nbsp;key=HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User&nbsp;Shell&nbsp;Folders&nbsp; 
call&nbsp;:addReg&nbsp;"%key%"&nbsp;"AppData"&nbsp;"REG_EXPAND_SZ"&nbsp;"%USERPROFILE%\AppData\Roaming"&nbsp; 
set&nbsp;key=HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User&nbsp;Shell&nbsp;Folders&nbsp; 
call&nbsp;:addReg&nbsp;"%key%"&nbsp;"AppData"&nbsp;"REG_EXPAND_SZ"&nbsp;"%USERPROFILE%\AppData\Roaming"&nbsp; 
set&nbsp;key=HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User&nbsp;Shell&nbsp;Folders&nbsp; 
call&nbsp;:addReg&nbsp;"%key%"&nbsp;"AppData"&nbsp;"REG_EXPAND_SZ"&nbsp;"%USERPROFILE%\AppData\Roaming"&nbsp; 
set&nbsp;key=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate&nbsp; 
call&nbsp;:addReg&nbsp;"%key%"&nbsp;"AllowOSUpgrade"&nbsp;"REG_DWORD"&nbsp;"1"&nbsp; 
reg&nbsp;add&nbsp;"HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup"&nbsp;/f&nbsp; 
set&nbsp;key=HKLM\Software\Microsoft\Windows\CurrentVersion\Internet&nbsp;Settings\ZoneMap\Domains&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\microsoft.com\update"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\microsoft.com\update"&nbsp;"https"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\microsoft.com\windowsupdate"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\update.microsoft.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\update.microsoft.com"&nbsp;"https"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\windowsupdate.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\windowsupdate.microsoft.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\download.microsoft.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\windowsupdate.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\windowsupdate.com"&nbsp;"https"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\windowsupdate.com\download"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\windowsupdate.com\download"&nbsp;"https"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\download.windowsupdate.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\download.windowsupdate.com"&nbsp;"https"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\windows.com\wustat"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\wustat.windows.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\microsoft.com\ntservicepack"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\ntservicepack.microsoft.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\microsoft.com\ws"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\microsoft.com\ws"&nbsp;"https"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\ws.microsoft.com"&nbsp;"http"&nbsp;"REG_DWORD"&nbsp;"2"&nbsp; 
call&nbsp;:addReg&nbsp;"%key%\ws.microsoft.com"&nbsp;"https"&nbsp;"REG_DWORD"&nbsp;"2" 
regsvr32.exe atl.dll /s 
regsvr32.exe urlmon.dll /s 
regsvr32.exe mshtml.dll /s 
regsvr32.exe shdocvw.dll /s 
regsvr32.exe browseui.dll /s 
regsvr32.exe jscript.dll /s 
regsvr32.exe vbscript.dll /s 
regsvr32.exe scrrun.dll /s 
regsvr32.exe msxml.dll /s 
regsvr32.exe msxml3.dll /s 
regsvr32.exe msxml6.dll /s 
regsvr32.exe actxprxy.dll /s 
regsvr32.exe softpub.dll /s 
regsvr32.exe wintrust.dll /s 
regsvr32.exe dssenh.dll /s 
regsvr32.exe rsaenh.dll /s 
regsvr32.exe gpkcsp.dll /s 
regsvr32.exe sccbase.dll /s 
regsvr32.exe slbcsp.dll /s 
regsvr32.exe cryptdlg.dll /s 
regsvr32.exe oleaut32.dll /s 
regsvr32.exe ole32.dll /s 
regsvr32.exe shell32.dll /s 
regsvr32.exe initpki.dll /s 
regsvr32.exe wuapi.dll /s 
regsvr32.exe wuaueng.dll /s 
regsvr32.exe wuaueng1.dll /s 
regsvr32.exe wucltui.dll /s 
regsvr32.exe wups.dll /s 
regsvr32.exe wups2.dll /s 
regsvr32.exe wuweb.dll /s 
regsvr32.exe qmgr.dll /s 
regsvr32.exe qmgrprxy.dll /s 
regsvr32.exe wucltux.dll /s 
regsvr32.exe muweb.dll /s 
regsvr32.exe wuwebv.dll /s 
netsh winsock reset 
netsh winhttp reset proxy 
net start bits 
net start wuauserv 
net start appidsvc 
net start cryptsvc