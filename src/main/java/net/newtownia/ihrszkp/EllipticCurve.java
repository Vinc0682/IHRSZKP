package net.newtownia.ihrszkp;

import javafx.util.Pair;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.util.Random;

public class EllipticCurve
{
    private static ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("curve25519");

    public static ECPoint getPoint(byte[] bytes)
    {
        return spec.getCurve().decodePoint(bytes);
    }

    public static ECPoint multiply(ECPoint point, byte[] factor)
    {
        return point.multiply(BigIntegers.fromUnsignedByteArray(factor));
    }

    public static byte[] multiply(byte[] point, byte[] factor)
    {
        return multiply(getPoint(point), factor).getEncoded(true);
    }

    public static ECPoint getPublicKey(byte[] factor)
    {
        return multiply(spec.getG(), factor);
    }

    public static Pair<byte[], byte[]> generateKeyPair(Random rnd)
    {
        byte[] privateKey = new byte[32];
        rnd.nextBytes(privateKey);
        maskPrivateKey(privateKey);

        return new Pair<>(privateKey, getPublicKey(privateKey).getEncoded(true));
    }

    public static void maskPrivateKey(byte[] key)
    {
        key[0]  &= 248;
        key[31] &= 127;
        key[31] |= 64;
    }

    public static BigInteger getOrder()
    {
        return spec.getCurve().getOrder();
    }
}
