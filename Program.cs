/*
 * Fast Domain Dump - Data mine massive domain controllers in minutes
 */

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;

namespace FastDomainDump
{
	class Program
	{
    	private const int ERROR_MORE_DATA = 234;
    	
		public enum SV_TYPES:uint
		{
			SV_TYPE_DOMAIN_CTRL= 0x00000008,
			SV_TYPE_DOMAIN_BAKCTRL= 0x00000010,
		};
		
		[DllImport("netapi32.dll")]
		extern static int NetUserEnum([MarshalAs(UnmanagedType.LPWStr)]
		                              string servername,
		                              int level,
		                              int filter,
		                              out IntPtr bufptr,
		                              int prefmaxlen,
		                              out int entriesread,
		                              out int totalentries,
		                              ref int resume_handle);
		
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct USER_INFO_3
		{
			public string name;
			public string password;
			public int password_age;
			public int priv;
			public string home_dir;
			public string comment;
			public int flags;
			public string script_path;
			public int auth_flags;
			public string full_name;
			public string usr_comment;
			public string parms;
			public string workstations;
			public int last_logon;
			public int last_logoff;
			public int acct_expires;
			public int max_storage;
			public int units_per_week;
			public IntPtr logon_hours;    // This is a PBYTE
			public int bad_pw_count;
			public int num_logons;
			public string logon_server;
			public int country_code;
			public int code_page;
			public int user_id;
			public int primary_group_id;
			public string profile;
			public string home_dir_drive;
			public int password_expired;
		}
		
		[DllImport("netapi32.dll",EntryPoint="NetServerEnum")]
		public static extern int NetServerEnum(
			int servername,
			int level,
			out IntPtr bufptr,
			int prefmaxlen,
			ref int entriesread,
			ref int totalentries,
			SV_TYPES servertype,
			[MarshalAs(UnmanagedType.LPWStr)]string domain,
			IntPtr resume_handle);

		[DllImport("netapi32.dll",EntryPoint="NetApiBufferFree")]
		public static extern int NetApiBufferFree(IntPtr buffer);
		
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		private struct SERVER_INFO_100
		{
		    public int PlatformId;
		    [MarshalAs(UnmanagedType.LPTStr)]
		    public string Name;
		}
		public static string UnixToStr( double unixTimeStamp )
		{
			if (unixTimeStamp < 1)
				return "";
		    // Unix timestamp is seconds past epoch
		    System.DateTime dtDateTime = new DateTime(1970,1,1,0,0,0,0);
		    dtDateTime = dtDateTime.AddSeconds( unixTimeStamp ).ToLocalTime();
		    return dtDateTime.ToShortDateString() + " " + dtDateTime.ToShortTimeString();
		}
		public static string FlagsToString(int flags) 
		{
			string output = "";
			if ((flags & 0x00000001) != 0)
				output += "UF_SCRIPT,";
			if ((flags & 0x00000002) != 0)
				output += "UF_ACCOUNTDISABLE,";
			if ((flags & 0x00000008) != 0)
				output += "UF_HOMEDIR_REQUIRED,";
			if ((flags & 0x00000010) != 0)
				output += "UF_LOCKOUT,";
			if ((flags & 0x00000020) != 0)
				output += "UF_PASSWD_NOTREQD,";
			if ((flags & 0x00000040) != 0)
				output += "UF_PASSWD_CANT_CHANGE,";
			if ((flags & 0x00000080) != 0)
				output += "UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,";			
			if ((flags & 0x00000100) != 0)
				output += "UF_TEMP_DUPLICATE_ACCOUNT,";
			if ((flags & 0x00000200) != 0)
				output += "UF_NORMAL_ACCOUNT,";
			if ((flags & 0x00000800) != 0)
				output += "UF_INTERDOMAIN_TRUST_ACCOUNT,";
			if ((flags & 0x00001000) != 0)
				output += "UF_WORKSTATION_TRUST_ACCOUNT,";
			if ((flags & 0x00002000) != 0)
				output += "UF_SERVER_TRUST_ACCOUNT,";
			if ((flags & 0x00010000) != 0)
				output += "UF_DONT_EXPIRE_PASSWD,";
			if ((flags & 0x00020000) != 0)
				output += "UF_MNS_LOGON_ACCOUNT,";			
			if ((flags & 0x00040000) != 0)
				output += "UF_SMARTCARD_REQUIRED,";
			if ((flags & 0x00080000) != 0)
				output += "UF_TRUSTED_FOR_DELEGATION,";
			if ((flags & 0x00100000) != 0)
				output += "UF_NOT_DELEGATED,";
			if ((flags & 0x00200000) != 0)
				output += "UF_USE_DES_KEY_ONLY,";
			if ((flags & 0x00400000) != 0)
				output += "UF_DONT_REQUIRE_PREAUTH,";
			if ((flags & 0x00800000) != 0)
				output += "UF_PASSWORD_EXPIRED,";
			if ((flags & 0x01000000) != 0)
				output += "UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,";
			if ((flags & 0x02000000) != 0)
				output += "UF_NO_AUTH_DATA_REQUIRED,";
			if ((flags & 0x04000000) != 0)
				output += "UF_PARTIAL_SECRETS_ACCOUNT,";
			if ((flags & 0x08000000) != 0)
				output += "UF_USE_AES_KEYS,";
			return output;
		}
		
		public static string AuthFlagsToString(int flags)
		{
			string output = "";
			if ((flags & 1) != 0)
				output += "AF_OP_PRINT,";
			if ((flags & 2) != 0)
				output += "AF_OP_COMM,";
			if ((flags & 4) != 0)
				output += "AF_OP_SERVER,";
			if ((flags & 8) != 0)
				output += "AF_OP_ACCOUNTS,";
			return output;
		}
		
		public static string PrivToString(int priv)
		{
			switch(priv) {
				case 0:
					return "USER_PRIV_GUEST";
				case 1:
					return "USER_PRIV_USER";
				case 2:
					return "USER_PRIV_ADMIN";
			}
			return "UNKNOWN USER PRIV";
		}
				
		public static void DumpServer(string serverName) {
			StreamWriter writer = new StreamWriter(serverName + ".txt");
			IntPtr resume_handle = IntPtr.Zero;
			IntPtr ptr = IntPtr.Zero;
			int resume = 0;
			double total_counted = 0;
			double max = 0;
			int totalentries = 0;
			int entriesread = 0;
			int prefmaxlen = 1048576 * 10; // 1 MB * 10
			Stopwatch sw = new Stopwatch();
			writer.WriteLine("Name\tFull Name\tComment\tUser Comment\tFlags\tAuth Flags\tPw Age\tExpired Pw?\tLast Logon\tLast Logoff\tExpiry Date\tPriv\tBad Pw Count\tProfile\tHomedir\tMax Storage\tWorkstations");
			
			while (true) {
				sw.Start();
				int status = NetUserEnum(serverName, 3, 2, out ptr, prefmaxlen, out entriesread, out totalentries, ref resume);
				sw.Stop();
				if (status != ERROR_MORE_DATA && status != 0) {
					Console.WriteLine("Error: " + status);
					break;
				}
				
				
				total_counted += entriesread;
				if (max == 0)
						max = totalentries;
				
				IntPtr iter = ptr;
		        for(int i=0; i < entriesread; i++)
		        {
		            USER_INFO_3 user = (USER_INFO_3)Marshal.PtrToStructure(iter, typeof(USER_INFO_3)); 
		            iter = (IntPtr)((int)iter + Marshal.SizeOf(user));
		            writer.Write(user.name);
		            writer.Write("\t");
		            writer.Write(user.full_name);
		            writer.Write("\t");
		            writer.Write(user.comment);
		            writer.Write("\t");
		            writer.Write(user.usr_comment);
		            writer.Write("\t");
		            writer.Write(FlagsToString(user.flags));
		            writer.Write("\t");
		            writer.Write(AuthFlagsToString(user.auth_flags));
		            writer.Write("\t");
		            writer.Write(user.password_age + "s - " + user.password_age / (60*60*24) + "days");
		            writer.Write("\t");
		            writer.Write(user.password_expired);
		            writer.Write("\t");
		            writer.Write(UnixToStr(user.last_logon));
		            writer.Write("\t");
		            writer.Write(UnixToStr(user.last_logoff));
		            writer.Write("\t");
		            writer.Write(UnixToStr(user.acct_expires));
		            writer.Write("\t");
		            writer.Write(user.priv);
		            writer.Write("\t");
		            writer.Write(user.bad_pw_count);
		            writer.Write("\t");
		            writer.Write(user.profile);
		            writer.Write("\t");
		            writer.Write(user.home_dir_drive);
		            writer.Write("\t");
		            writer.Write(user.max_storage);
		            writer.Write("\t");
		            writer.Write(user.workstations);
		            writer.Write("\t");
		            writer.WriteLine();
		        }
		        writer.Flush();
		        
		        NetApiBufferFree(ptr);
		        
		        Console.WriteLine(String.Format("{0:#.##}% {1} / {2} in {3}s - {4:#.##} users/sec", (total_counted / max) * 100 , total_counted, max, sw.ElapsedMilliseconds/1000, total_counted / (sw.ElapsedMilliseconds / 1000)));
				
				if (status == 0) {
					break;
				}
		        
			}
			writer.Close();
			Console.WriteLine("Done.");
			
		}
		
		
		public static void Main(string[] args)
		{
			IntPtr resume_handle = IntPtr.Zero;
			IntPtr ptr = IntPtr.Zero;
			int totalentries = 0;
			int entriesread = 0;
			const int prefmaxlen = 65535;
			List<string> dcs = new List<string>();
			
			if (args.Length < 2) 
			{
				Console.WriteLine("Need more args: FastDomainDump [domain|server] DOMAIN/SERVER");
				return;
			}
			
			if (args[0] == "domain") {	
				int status = NetServerEnum(0, 100, out ptr, prefmaxlen, ref entriesread, ref totalentries, SV_TYPES.SV_TYPE_DOMAIN_CTRL | SV_TYPES.SV_TYPE_DOMAIN_BAKCTRL, args[1], resume_handle);
				
				if (status != 0) {
					Console.WriteLine("NetServerEnum failed.");
					return;
				}
				
				for(int i=0; i<entriesread; i++)
	            {
	            	// cast pointer to a SERVER_INFO_101 structure
	                SERVER_INFO_100 server = (SERVER_INFO_100)Marshal.PtrToStructure(ptr,typeof(SERVER_INFO_100));
	                Console.WriteLine("Adding server to check: " + server.Name);
	                dcs.Add(server.Name);
	               	//Cast the pointer to a ulong so this addition will work on 32-bit or 64-bit systems.
	                ptr = (IntPtr)((ulong)ptr + (ulong)Marshal.SizeOf(server));
	            }
				
				foreach(string dc in dcs) {
					Console.WriteLine("Dumping Server: " + dc);
					DumpServer(dc);
				}
			} else if (args[0] == "server") {
				DumpServer(args[1]);
			}
			
			Console.ReadKey(true);
		}
	}
}