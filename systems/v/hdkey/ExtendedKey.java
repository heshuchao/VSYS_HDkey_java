package systems.v.hdkey;

import java.math.BigInteger;
import java.util.Arrays;

public class ExtendedKey {

	private final static int HardenedKeyStart = 0x70000000;
	private final static byte[] vsysPubPrefix = {0x55, 0x3f, (byte)0x8b, (byte)0xe7, 0x68, (byte)0x93, 0x66};
	private final static byte[] vsysPrvPrefix = {0x55, 0x3f, (byte)0x8b, (byte)0xe7, 0x4c, (byte)0xe8, 0x33};
	
	private byte depth;
	private byte[] parentFingertPrint;
	private int serializes;
	private byte[] chainCode;
	private byte[] key;
	private boolean isPrivate;
	
	public ExtendedKey(byte depth, byte[] parentFingertPrint, int serializes, byte[] chainCode, byte[] key, boolean isPrivate) 
	{
		this.depth = depth;
		this.parentFingertPrint = parentFingertPrint;
		this.serializes = serializes;
		this.chainCode = chainCode;
		this.key = key;
		this.isPrivate = isPrivate;
	}
	
	private byte[] generateParentFingerPrint(byte[] key, boolean isPrivate)
	{
		byte[] fingerPrint = new byte[4];
		if(isPrivate)
		{
			byte[] pubkey = new byte[32];
			curve_points.keygen_Ed(pubkey, key);
			byte[] hash = Hash.getDigest("SHA-256", null, pubkey);
			if(hash == null)
				return null;
			System.arraycopy(hash, 0, fingerPrint, 0, 4);
		}else {
			byte[] hash = Hash.getDigest("SHA-256", null, key);
			if(hash == null)
				return null;
			System.arraycopy(hash, 0, fingerPrint, 0, 4);
		}
		return fingerPrint;
	}
	
	private byte[] generateI(byte[] data, byte[] key, int serializes)
	{
		return Hash.getDigest("HmacSHA512", key,  data, Util.int2Bytes(serializes));
	}
	
	private static byte[] getPrivateChildFromPrivateParent(byte[] il, byte[] prikey)
	{
		byte[] ilLittleEndian = new byte[28];
		System.arraycopy(il, 0, ilLittleEndian, 0, 28);
		Util.reverseArray(ilLittleEndian);
		BigInteger ilNum = new BigInteger(1, ilLittleEndian);
		
		Util.reverseArray(prikey);

		BigInteger kpr = new BigInteger(1, prikey);
		Util.reverseArray(prikey);
		
		BigInteger num8 = new BigInteger("8");
		
		ilNum = ilNum.multiply(num8);

		
		ilNum = ilNum.add(kpr);

		
		byte[] priChild = ilNum.toByteArray();
		if(priChild.length < 32)
		{
			byte[] tmp = new byte[32];
			System.arraycopy(priChild, 0, tmp, 0, priChild.length);
			priChild = tmp;
		}
		
		Util.reverseArray(priChild);

		return priChild;
	}
	
	private static byte[] getPublicChildFromPublicParent(byte[] il, byte[] pubkey)
	{
		byte[] ilLittleEndian = new byte[28];
		System.arraycopy(il, 0, ilLittleEndian, 0, 28);
		Util.reverseArray(ilLittleEndian);
		BigInteger ilNum = new BigInteger(1, ilLittleEndian);
		
		BigInteger num8 = new BigInteger("8");
		
		ilNum = ilNum.multiply(num8);

		byte[] il2 = ilNum.toByteArray();
		if(il2.length < 32)
		{
			byte[] tmp = new byte[32];
			System.arraycopy(il2, 0, tmp, 32 - il2.length, il2.length);
			il2 = tmp;
		}
		Util.reverseArray(il2);
		
		byte[] pubChild = new byte[32];
		if(curve_points.scalarmultBaseAdd(pubkey, il2, pubChild))
			return pubChild;
		return null;
	}

	
	public ExtendedKey generatePrivateChild(int serializes) throws HDkeyException
	{
		if(this.depth == 1<<8 -1)
			throw new HDkeyException("Too much indices!");
		if(!this.isPrivate)
			throw new HDkeyException("Cannot derived keys from public parent to private child!");
		
		byte[] i;
		if(serializes >= HardenedKeyStart)
			i = generateI(this.key, this.chainCode, serializes);
		else
		{
			byte[] point = new byte[32];
			curve_points.keygen_Ed(point, this.key);
			i = generateI(point, this.chainCode, serializes);
		}
		
		byte[] il = new byte[32];
		byte[] ir = new byte[32];
		
		System.arraycopy(i, 0, il, 0, 32);
		System.arraycopy(i, 32, ir, 0, 32);
		
		byte[] childKey = getPrivateChildFromPrivateParent(il, this.key);
		if(childKey == null)
			throw new HDkeyException("Cannot derived keys by this serialize, infinity point detected!");
		
		byte[] parentFingerPrint = generateParentFingerPrint(this.key, this.isPrivate);
		if(parentFingerPrint == null)
			throw new HDkeyException("Hash error!");
		
		return new ExtendedKey((byte)(this.depth + 1), parentFingerPrint, serializes, ir, childKey, true);
	}
	
	public ExtendedKey generatePublicChild(int serializes) throws HDkeyException
	{
		if(!this.isPrivate)
		{
			if(serializes >= HardenedKeyStart)
				throw new HDkeyException("Cannot derived hardened keys from public parent!");
			byte[] i = generateI(this.key, this.chainCode, serializes);
			
			byte[] il = new byte[32];
			byte[] ir = new byte[32];
			
			System.arraycopy(i, 0, il, 0, 32);
			System.arraycopy(i, 32, ir, 0, 32);
			
			byte[] childKey = getPublicChildFromPublicParent(il, this.key);
			if(childKey == null)
				throw new HDkeyException("Cannot derived keys by this serialize, infinity point detected!");
			
			byte[] parentFingerPrint = generateParentFingerPrint(this.key, false);
			if(parentFingerPrint == null)
				throw new HDkeyException("Hash error!");
			
			return new ExtendedKey((byte)(this.depth + 1), parentFingerPrint, serializes, ir, childKey, false);
		}

		ExtendedKey childPri = generatePrivateChild(serializes);
		byte[] childKey = new byte[32];
		curve_points.keygen_Ed(childKey, childPri.key);
		return new ExtendedKey((byte)(this.depth + 1), childPri.parentFingertPrint, serializes, childPri.chainCode,childKey,  false);
	}
	
	private static ExtendedKey initRootFromSeed(byte[] seed)
	{
		byte[] i = Hash.getDigest("SHA-512", null, seed);
		i[0] &= 248;
		i[31] &= 127;
		i[31] |= 64;
		
		byte[] il = new byte[32];
		byte[] ir = new byte[32];
		System.arraycopy(i, 0, il, 0, 32);
		System.arraycopy(i, 32, ir, 0, 32);
		byte[] rootParentFingerPrint = {0x00,0x00,0x00,0x00};
		return new ExtendedKey((byte)0, rootParentFingerPrint, 0, ir, il, true);
	}
	
	private static ExtendedKey derivedPrivateKeyWithAbsolutePath(byte[] seed, String derivedPath) throws HDkeyException
	{
		String path = derivedPath.replace(" ", "");
		
		if(path == "m" || path == "/" || path == "")
			return ExtendedKey.initRootFromSeed(seed);
		
		if(path.indexOf("m/") != 0)
			throw new HDkeyException("Invalid path to derived keys!");
		
		ExtendedKey privateKey = ExtendedKey.initRootFromSeed(seed);
		
		path = path.substring(2);
		String[] elements = path.split("/");
		
		for (String elem : elements) {
			if(elem.length() == 0)
				throw new HDkeyException("Invalid path to derived keys!");
			
			int hdSerializes = 0;
			
			if(elem.contains("'"))
			{
				if(elem.endsWith("'"))
				{
					elem = elem.replace("'", "");
					int index = Integer.valueOf(elem).intValue();
					hdSerializes = index + HardenedKeyStart;
				}
				else 
				{
					throw new HDkeyException("Invalid path to derived keys!");
				}
			}
			else 
			{
				hdSerializes = Integer.valueOf(elem).intValue();
			}
			
			privateKey = privateKey.generatePrivateChild(hdSerializes);
		}
		return privateKey;
	}
	
	private ExtendedKey getPublicExtendedStruct()
	{
		if(!isPrivate)
			return this;
		byte[] pubkey = new byte[32];
		
		curve_points.keygen_Ed(pubkey, key);
		
		return new ExtendedKey(depth, parentFingertPrint, serializes, chainCode, pubkey, false);
	}
	
	private static ExtendedKey derivedPublicKeyWithAbsolutePath(byte[] seed, String derivedPath) throws HDkeyException
	{
		ExtendedKey privateKey = ExtendedKey.derivedPrivateKeyWithAbsolutePath(seed, derivedPath);
		return privateKey.getPublicExtendedStruct();
	}

	private byte[] getVSYSPublicPoint()
	{
		byte[] vsysPoint = new byte[32];
		curve_points.convert_Ed_to_X(vsysPoint, key);
		return vsysPoint;
	}
	
	private String encodeToString() {

		byte[] byteStruct = new byte[80];
		if(isPrivate) 
		{
			System.arraycopy(vsysPrvPrefix, 0, byteStruct, 0, 7);
		}
		else
		{
			System.arraycopy(vsysPubPrefix, 0, byteStruct, 0, 7);
		}
		byteStruct[7] = depth;
		System.arraycopy(parentFingertPrint, 0, byteStruct, 8, 4);
		byte[] serBytes = Util.int2Bytes(serializes);
		System.arraycopy(serBytes, 0, byteStruct, 12, 4);
		System.arraycopy(chainCode, 0, byteStruct, 16, 32);
		System.arraycopy(key, 0, byteStruct, 48, 32);
		return Base58.encode(byteStruct);
	}
	
	private static ExtendedKey decodeFromString(String data) throws HDkeyException
	{
		byte[] byteStruct = Base58.decode(data);
		if(byteStruct.length == 0 || byteStruct.length != 80)
		{
			throw new HDkeyException("Invalid key data!");
		}
		byte[] prefix = Arrays.copyOfRange(byteStruct, 0, 7);
		boolean isPrivate;
		if(Arrays.equals(prefix, vsysPrvPrefix))
			isPrivate = true;
		else if(Arrays.equals(prefix, vsysPubPrefix))
			isPrivate = false;
		else
			throw new HDkeyException("Invalid key data!");
		byte depth = byteStruct[7];
		byte[] parentFingerPrint = Arrays.copyOfRange(byteStruct, 8, 12);
		int serialize = Util.bytes2Int( Arrays.copyOfRange(byteStruct, 12, 16));
		byte[] chainCode = Arrays.copyOfRange(byteStruct, 16, 48);
		byte[] key = Arrays.copyOfRange(byteStruct, 48, 80);
		
		return new ExtendedKey(depth, parentFingerPrint, serialize, chainCode, key, isPrivate);
	}
	
	public static String generateParentPublicKey(byte[] seed, String path) throws HDkeyException
	{
		ExtendedKey publicKey = ExtendedKey.derivedPublicKeyWithAbsolutePath(seed, path);
		return publicKey.encodeToString();
	}
	
	public static byte[] generateChildPublicKeyBytes(String parentKeyStr, int serialize) throws HDkeyException
	{
		ExtendedKey parentKey = ExtendedKey.decodeFromString(parentKeyStr);
		ExtendedKey childKey = parentKey.generatePublicChild(serialize);
		return childKey.getVSYSPublicPoint();
	}
	
	public static byte[] generatePrivateKey(byte[] seed, String path) throws HDkeyException
	{
		ExtendedKey privateKey = ExtendedKey.derivedPrivateKeyWithAbsolutePath(seed, path);
		return privateKey.key;
	}
}









