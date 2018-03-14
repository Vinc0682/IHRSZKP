package net.newtownia.ihrszkp;

import javafx.util.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import javax.swing.text.ElementIterator;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class IHRSZKP
{
    private static SecureRandom rnd = new SecureRandom();

    public static Pair<byte[], List<byte[]>> issue(List<byte[]> groupPublicKeys)
    {
        Pair<byte[], byte[]> maskPair = EllipticCurve.generateKeyPair(rnd);

        List<byte[]> verifyKeys = new ArrayList<>();
        for (byte[] publicKey : groupPublicKeys)
            verifyKeys.add(EllipticCurve.multiply(publicKey, maskPair.getKey()));

        return new Pair<>(maskPair.getValue(), verifyKeys);
    }

    // findOwnIndex is var time!!!
    public static Pair<byte[][], byte[][]> proof(byte[] privateKey, List<byte[]> verifyKeys, byte[] mask,
                                                         byte[] challenge) throws NoSuchAlgorithmException
    {
        // Find the index of the private masked key.
        int j = findOwnIndex(verifyKeys, privateKey, mask);
        if (j < 0)
            throw  new IllegalStateException("Not member of the group.");

        int n = verifyKeys.size();
        ECPoint maskPoint = EllipticCurve.getPoint(mask);

        // Initialize s with random data.
        byte[][] s = new byte[n][32];
        for (int i = 0; i < verifyKeys.size(); i += 1)
        {
            rnd.nextBytes(s[i]);
            EllipticCurve.maskPrivateKey(s[i]);
        }

        // Initialize X.
        byte[][] X = new byte[n][32];

        // Generate a random alpha.
        byte[] alpha = new byte[32];
        rnd.nextBytes(alpha);
        EllipticCurve.maskPrivateKey(alpha);

        // Calculate the initial X.
        X[j] = EllipticCurve.multiply(mask, alpha);
        byte[] c = hash(challenge, X[j]);

        // Loop through the ring and calculate the X's.
        for (int i = (j + 1) % n; i != j; i = (i + 1) % n)
        {
            X[i] = calculateX(s[i], c, maskPoint, verifyKeys.get(i));
            c = hash(challenge, X[i]);
        }

        // Calculate s_j.
        BigInteger xc = BigIntegers.fromUnsignedByteArray(c).multiply(BigIntegers.fromUnsignedByteArray(privateKey));
        BigInteger sj = BigIntegers.fromUnsignedByteArray(alpha).subtract(xc).mod(EllipticCurve.getOrder());

        if (sj.compareTo(BigInteger.ZERO) < 0)
            throw new IllegalStateException("Sj is smaller than zero.");

        // Ensure that the final byte array is constant length.
        byte[] tmp = sj.toByteArray();
        byte[] sj_array = new byte[32];
        System.arraycopy(tmp, 0, sj_array, 32 - tmp.length, tmp.length);
        s[j] = sj_array;

        return new Pair<>(s, X);
    }

    // IS DEFINITELY NOT CONSTANT TIME; BUT I GUESS IT DOESN'T NEED TO BE SO.
    public static boolean verify(byte[][] s, byte[][] x, List<byte[]> verifyKeys, byte[] mask, byte[] challenge) throws NoSuchAlgorithmException
    {
        int n = s.length;
        ECPoint maskPoint = EllipticCurve.getPoint(mask);

        byte[] c = hash(challenge, x[n - 1]);
        for (int i = 0; i < n; i += 1)
        {
            // Check weather the given X is reconstructable and abort if not so.
            if (!Arrays.equals(calculateX(s[i], c, maskPoint, verifyKeys.get(i)), x[i]))
                return false;
            c = hash(challenge, x[i]);
        }
        return true;
    }

    private static int findOwnIndex(List<byte[]> verifyKeys, byte[] privateKey, byte[] maskPoint)
    {
        byte[] ownVerifyKey = EllipticCurve.multiply(maskPoint, privateKey);
        for (int i = 0; i < verifyKeys.size(); i += 1)
            if (Arrays.equals(ownVerifyKey, verifyKeys.get(i)))
                return i;
        return -1;
    }

    private static byte[] calculateX(byte[] s, byte[] c, ECPoint maskPoint, byte[] verifyKey)
    {
        return EllipticCurve.multiply(maskPoint, s)
                .add(EllipticCurve.multiply(EllipticCurve.getPoint(verifyKey), c))
                .getEncoded(true);
    }

    private static byte[] hash(byte[] challenge, byte[] x) throws NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(challenge);
        digest.update(x);
        return digest.digest();
    }


}
