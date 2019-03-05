package systems.v.hdkey;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Hash {
	
	public static byte[] getDigest(String hashType,byte[] key, byte[] ...data)
	{
		if(data.length == 0)
		{
			return null;
		}

		MessageDigest messageDigest;
		try {
			if(key == null)
			{
				messageDigest = MessageDigest.getInstance(hashType);
				for (byte[] bs : data) {
					messageDigest.update(bs);
				}
				return messageDigest.digest();
			}
			Mac messageMacDigest = Mac.getInstance(hashType);
			SecretKeySpec keySpec = new SecretKeySpec(key, hashType);
			messageMacDigest.init(keySpec);
			for (byte[] bs : data) {
				messageMacDigest.update(bs);
			}
			return messageMacDigest.doFinal();
		}catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (InvalidKeyException e) {
	        e.printStackTrace();
	    }
		return null;
	}
}
