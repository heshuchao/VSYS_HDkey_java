package systems.v.hdkey;

public class Util {
	
	public static byte[] int2Bytes(int integer)
	{
        byte[] bytes=new byte[4];
 
        bytes[3]=(byte)integer;
        bytes[2]=(byte)(integer>>8);
        bytes[1]=(byte)(integer>>16);
        bytes[0]=(byte)(integer>>24);
        
        return bytes;
	}
	
	public static int bytes2Int(byte[] bytes)
	{
		return bytes[3] & 0xFF | (int)(bytes[2] & 0xFF) << 8 | (int)(bytes[1] & 0xFF) << 16 | (int)(bytes[0] & 0xFF) << 24;
	}
	
	public static void reverseArray(byte[] array)
	{
		for (int i = 0; i < array.length / 2; i++) 
		{
			byte tmp = array[i];
			array[i] = array[array.length - 1 - i];
			array[array.length - 1 - i] = tmp;
		}
	}
}
