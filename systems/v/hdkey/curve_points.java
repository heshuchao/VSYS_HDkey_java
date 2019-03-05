package systems.v.hdkey;

import org.whispersystems.curve25519.java.crypto_verify_32;
import org.whispersystems.curve25519.java.fe_1;
import org.whispersystems.curve25519.java.fe_add;
import org.whispersystems.curve25519.java.fe_frombytes;
import org.whispersystems.curve25519.java.fe_invert;
import org.whispersystems.curve25519.java.fe_isnegative;
import org.whispersystems.curve25519.java.fe_isnonzero;
import org.whispersystems.curve25519.java.fe_mul;
import org.whispersystems.curve25519.java.fe_neg;
import org.whispersystems.curve25519.java.fe_pow22523;
import org.whispersystems.curve25519.java.fe_sq;
import org.whispersystems.curve25519.java.fe_sub;
import org.whispersystems.curve25519.java.fe_tobytes;
import org.whispersystems.curve25519.java.ge_double_scalarmult;
import org.whispersystems.curve25519.java.ge_p2;
import org.whispersystems.curve25519.java.ge_p3;
import org.whispersystems.curve25519.java.ge_p3_tobytes;
import org.whispersystems.curve25519.java.ge_scalarmult_base;

class ge{
	
	static int[] d = {-10913610,13857413,-15372611,6949391,114729,-8787816,-6275908,-3247719,-18696448,-12055116} ;
	static int[] sqrtm1 = {-32595792,-7943725,9377950,3500415,12389472,-272473,-25146209,-2005654,326686,11406482} ;
	
	public static int frombytes_vartime(ge_p3 h,byte[] s)
	{
	  int[] u = new int[10];
	  int[] v = new int[10];
	  int[] v3 = new int[10];
	  int[] vxx = new int[10];
	  int[] check = new int[10];

	  fe_frombytes.fe_frombytes(h.Y,s);
	  fe_1.fe_1(h.Z);
	  fe_sq.fe_sq(u,h.Y);
	  fe_mul.fe_mul(v,u,d);
	  fe_sub.fe_sub(u,u,h.Z); 
	  fe_add.fe_add(v,v,h.Z);

	  fe_sq.fe_sq(v3,v);
	  fe_mul.fe_mul(v3,v3,v);
	  fe_sq.fe_sq(h.X,v3);
	  fe_mul.fe_mul(h.X,h.X,v);
	  fe_mul.fe_mul(h.X,h.X,u); 

	  fe_pow22523.fe_pow22523(h.X,h.X); 
	  fe_mul.fe_mul(h.X,h.X,v3);
	  fe_mul.fe_mul(h.X,h.X,u);

	  fe_sq.fe_sq(vxx,h.X);
	  fe_mul.fe_mul(vxx,vxx,v);
	  fe_sub.fe_sub(check,vxx,u);
	  if (fe_isnonzero.fe_isnonzero(check) != 0) 
	  {
	    fe_add.fe_add(check,vxx,u);
	    if (fe_isnonzero.fe_isnonzero(check) != 0) 
	    	return -1;
	    fe_mul.fe_mul(h.X,h.X,sqrtm1);
	  }

	  if (fe_isnegative.fe_isnegative(h.X) != ((s[31] >>> 7) & 0x01)) 
	  {
	    fe_neg.fe_neg(h.X,h.X);
	  }

	  fe_mul.fe_mul(h.T,h.X,h.Y);
	  return 0;
	}

}

class fe{
	
	public static boolean isreduced(byte[] s)
	{
		int[] f = new int[10]; 
		byte[] strict = new byte[32];
		
		fe_frombytes.fe_frombytes(f, s);
		fe_tobytes.fe_tobytes(strict, f);
		
		if(crypto_verify_32.crypto_verify_32(strict, s) != 0)
			return true;
		return false;
	}
	
	// y = (u - 1) / (u + 1)
	public static void montx_to_edy(int[] y, int[] u)
	{
		int[] one = new int[10];
		int[] um1 = new int[10];
		int[] up1 = new int[10];
		
		fe_1.fe_1(one);
		fe_sub.fe_sub(um1, u, one);
		fe_add.fe_add(up1, u, one);
		fe_invert.fe_invert(up1, up1);
		fe_mul.fe_mul(y, um1, up1);
	}
	
	// u = (1 + y) / (1 - y)
	public static void montx_from_edy(int[] u, int[] y)
	{
		int[] one = new int[10];
		int[] um1 = new int[10];
		int[] up1 = new int[10];
		
		fe_1.fe_1(one);
		fe_sub.fe_sub(um1, one, y);
		fe_invert.fe_invert(um1, um1);
		fe_add.fe_add(up1, y, one);
		fe_mul.fe_mul(u, um1, up1);
	}
	
	public static boolean is_zero(int[] f)
	{
		return fe_isnonzero.fe_isnonzero(f) == 1;
	}
	
	public static boolean is_one(int[] f)
	{
		  byte[] s = new byte[32];
		  byte[] one = new byte[32];
		  one[0] = 1;
		  fe_tobytes.fe_tobytes(s,f);
		  if(crypto_verify_32.crypto_verify_32(s,one) == 1)
			  return true;
		  return false;
	}
}

public class curve_points {
	
	public static void keygen_Ed(byte[] ed25519_pubkey_out, byte[] curve25519_privkey_in)
	{
		ge_p3 x = new ge_p3(); 
		
		// x = [curve25519_privkey_in] * B
		// B is the base point 
		ge_scalarmult_base.ge_scalarmult_base(x, curve25519_privkey_in);
		
		// x25519 point -> byte array
		ge_p3_tobytes.ge_p3_tobytes(ed25519_pubkey_out, x);
	}
	
	// convert an x25519 public key point to ed25519 public key point
	public static boolean convert_X_to_Ed(byte[] ed25519_pubkey_bytes, byte[]x25519_pubkey_bytes)
	{
		int[] u = new int[10];
		int[] y = new int[10];
		
		if(fe.isreduced(x25519_pubkey_bytes))
			return false;
		fe_frombytes.fe_frombytes(u, x25519_pubkey_bytes);
		fe.montx_to_edy(y, u);
		fe_tobytes.fe_tobytes(ed25519_pubkey_bytes, y);
		return true;
	}
	
	//convert an ed25519 public key point to x25519 public key point
	public static boolean convert_Ed_to_X(byte[] x25519_pubkey_bytes, byte[] ed25519_pubkey_bytes)
	{
		int[] u = new int[10];
		int[] y = new int[10];
		
		fe_frombytes.fe_frombytes(y, ed25519_pubkey_bytes);
		fe.montx_from_edy(u, y);
		fe_tobytes.fe_tobytes(x25519_pubkey_bytes, u);
		if(fe.isreduced(x25519_pubkey_bytes))
			return false;
		return true;
	}
	
	// point2 = point1 + [scalar] * B
	// B for base point
	// all in little endian
	public static boolean scalarmultBaseAdd(byte[] point1, byte[] scalar, byte[] point2)
	{
		ge_p3 P1 = new ge_p3();

		ge_p2 R = new ge_p2();
		
		int[] recip = new int[10];
		int[] x = new int[10];
		int[] y = new int[10];
		
		ge.frombytes_vartime(P1, point1);

		byte[] one = new byte[32];
		one[0] = 1;
		
		ge_double_scalarmult.ge_double_scalarmult_vartime(R, one, P1, scalar);
		
		fe_invert.fe_invert(recip, R.Z);
		fe_mul.fe_mul(x, R.X, recip);
		fe_mul.fe_mul(y, R.Y, recip);
		
		if(fe.is_zero(x) && fe.is_one(y))
			return false;
		fe_tobytes.fe_tobytes(point2, y);
		point2[31] ^= (fe_isnegative.fe_isnegative(x) << 7);
		
		return true;
	}
}


