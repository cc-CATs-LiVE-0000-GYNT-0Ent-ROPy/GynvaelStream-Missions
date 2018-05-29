# Mission 23 - GynvaelStream - solver v3
# https://www.youtube.com/watch?v=X7j2sisMKzk

#Another Solver in C# by Paweł Łukasik vel pawlos
#https://ctfs.ghost.io/gynvael-en-mission-023-solution/

#encrypt with AES in python using pycrypto lib
#https://gist.github.com/mimoo/11383475

import sys, base64, string, time, datetime, binascii
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import pkcs7

#From decompiled C# source - dnSpy - thanks to Rev` for advice	 
#string text = "GeronimoAlpha" + HelperProgram.GeneratePassword();
#byte[] Salt = new byte[] {10,20,30,40,50,60,70,80};
#string IV = "GBVPmky9FUDitUMeZmgUBA==";
#Modif Wed 16 May 2018 12:46:01 PM CEST
#dbname.enc  Epoch timestamp: 1526467561

iv = base64.b64decode("GBVPmky9FUDitUMeZmgUBA==")
print("\niv %s" % iv.encode('hex'))
salt = bytearray([10, 20, 30, 40, 50, 60, 70, 80])
print("salt %s encoded %s" % (salt,binascii.hexlify(bytearray(salt))))
keyBytes = 32
iterations = 300
ts = 1526467561   # 1526461548 desired value - taken from pawlos  
#ts = int(datetime.datetime(2018,05,16,9,5,49).strftime('%s'))

while True :
	pass = "GeronimoAlpha" + str(ts)

	derived_key = PBKDF2(pass, salt, keyBytes, iterations)
	#derived_key = '8F7F1CAB8B917432BD3038CE767FF448E3C745C67C23EECC50E36DCC5F9324DC'.decode("hex")
	
	#print("\nkey %s" % derived_key.encode("hex"))
	encoder = pkcs7.PKCS7Encoder()

	with open('dbname.db.enc', 'r') as encoded_secret:
		cipher = AES.new(derived_key, AES.MODE_CBC, iv)
		decoded = cipher.decrypt(base64.b64decode(encoded_secret.read()))[:15]
	if all(c in string.printable for c in decoded):
		print(decoded)
		print(decoded.encode('hex'))
		czas = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
		print(pass+' '+czas)
		break
	if ts%999  == 0:
		print("999 -------------- ")
	ts -= 1
	#

print("end")

'''
MISSION 023    gynvael.vexillium.org/ext/43bf753f    DIFFICULTY: [6/10]
Time: 13.37 UTC
Place: Intergalactic Security Agency HQ

Dear 1337 Agents,

We have to face it. Our Agency has elite IT department. But... we do not have
a budget for high skilled field operatives. Yet another rookie spy managed to
smuggle a microfilm out of rogue dictator's cottage. But due to the lack of an
IT knowledge he just become a victim of a phishing scam! His computer was
attacked by ransomware. It was not the Petya, but it also uses a military-grade
cipher.

Our CERT managed to extract a harmless part of the binary so we can share it
with you without any danger of further infections. You have to extract
infiltrated data before enemy's counterespionage team will take any action!

Here you have all data we have:
      http://gynvael.vexillium.org/ext/43bf753f
Good luck and remember, the time is running out!

Over and out.
--                                                        by foxtrot_charlie

If you find the answer, put it in the comments under this video! If you write a
blogpost / post your solution / code online, please add a link as well!
If you tweet about it, include @gynvael to let me know :)

P.S. Even though you should trust your agency more than you trust your family,
never ever run untrusted binaries on your own machine. If there is no other
option, use VM or sandbox.
P.S.2. Probably it's not important, but he has infected his computer this week.
P.S.3. Burn after read.

Source from decompilation:

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MissionASDF
{
	// Token: 0x02000002 RID: 2
	internal class HelperProgram
	{
		// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
		private static void Main(string[] args)
		{
			Console.WriteLine("Hello World!");
			string text = "GeronimoAlpha" + HelperProgram.GeneratePassword();
			Console.WriteLine(text);
			HelperProgram.Key = HelperProgram.CreateKey(text, 32);
			HelperProgram.EncryptData();
			HelperProgram.EncryptText("ThisIsAValidString");
		}

		// Token: 0x06000002 RID: 2 RVA: 0x0000208C File Offset: 0x0000028C
		private static string GeneratePassword()
		{
			return ((int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds).ToString();
		}

		// Token: 0x06000003 RID: 3 RVA: 0x000020C3 File Offset: 0x000002C3
		private static byte[] CreateKey(string password, int keyBytes = 32)
		{
			return new Rfc2898DeriveBytes(password, HelperProgram.Salt, 300).GetBytes(keyBytes);
		}

		// Token: 0x06000004 RID: 4 RVA: 0x000020DC File Offset: 0x000002DC
		private static void EncryptData()
		{
			string text = "dbname.db";
			if (!File.Exists(text))
			{
				Console.WriteLine("No such file!");
				Environment.Exit(-111);
			}
			byte[] array = File.ReadAllBytes(text);
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			rijndaelManaged.Key = HelperProgram.Key;
			rijndaelManaged.IV = Convert.FromBase64String(HelperProgram.IV);
			MemoryStream memoryStream = new MemoryStream();
			ICryptoTransform transform = rijndaelManaged.CreateEncryptor();
			CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
			cryptoStream.Write(array, 0, array.Length);
			cryptoStream.FlushFinalBlock();
			byte[] array2 = memoryStream.ToArray();
			memoryStream.Close();
			cryptoStream.Close();
			File.WriteAllText(text + ".enc", Convert.ToBase64String(array2, 0, array2.Length));
		}

		// Token: 0x06000005 RID: 5 RVA: 0x00002184 File Offset: 0x00000384
		private static void EncryptText(string text)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(text);
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			rijndaelManaged.Key = HelperProgram.Key;
			rijndaelManaged.IV = Convert.FromBase64String(HelperProgram.IV);
			MemoryStream memoryStream = new MemoryStream();
			ICryptoTransform transform = rijndaelManaged.CreateEncryptor();
			CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
			cryptoStream.Write(bytes, 0, bytes.Length);
			cryptoStream.FlushFinalBlock();
			byte[] array = memoryStream.ToArray();
			memoryStream.Close();
			cryptoStream.Close();
			Console.WriteLine(Convert.ToBase64String(array, 0, array.Length));
		}

		// Token: 0x04000001 RID: 1
		private static readonly byte[] Salt = new byte[]
		{
			10,
			20,
			30,
			40,
			50,
			60,
			70,
			80
		};

		// Token: 0x04000002 RID: 2
		private static readonly string IV = "GBVPmky9FUDitUMeZmgUBA==";

		// Token: 0x04000003 RID: 3
		private static byte[] Key;
	}
}
'''
