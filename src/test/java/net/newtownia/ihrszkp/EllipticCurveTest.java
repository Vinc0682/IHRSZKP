package net.newtownia.ihrszkp;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import javafx.util.Pair;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;


public class EllipticCurveTest
{
    private static final String BASEPOINT_HEX = "032AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A";

    private static ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("curve25519");

    @Test
    public void testDecoding()
    {
        byte[] testData = HexBin.decode(BASEPOINT_HEX);
        ECPoint point = EllipticCurve.getPoint(testData);

        Assert.assertEquals(point, spec.getG());
    }

    @Test
    public void testMultiplyWithPoint()
    {
        ECPoint basePoint = spec.getG();
        Assert.assertEquals(basePoint.multiply(new BigInteger("2")),
                EllipticCurve.multiply(basePoint, new byte[] { 2 }));
    }

    @Test
    public void testMultiplyWithBytes()
    {
        Assert.assertArrayEquals(spec.getG().multiply(new BigInteger("2")).getEncoded(true),
                EllipticCurve.multiply(HexBin.decode(BASEPOINT_HEX), new byte[] { 2 }));
    }

    @Test
    public void testPrivateKeyMask()
    {
        byte[] input = HexBin.decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        byte[] expected = HexBin.decode("0023456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD6F");
        EllipticCurve.maskPrivateKey(input);
        Assert.assertArrayEquals(input, expected);
    }

    @Test
    public void testGenerateKeyPairIsPair()
    {
        Pair<byte[], byte[]> pair = EllipticCurve.generateKeyPair(new SecureRandom());

        Assert.assertArrayEquals(pair.getValue(), EllipticCurve.getPublicKey(pair.getKey()).getEncoded(true));
    }

    @Test
    public void testGenerateKeyPairPrivateIsMasked()
    {
        byte[] privateKey = EllipticCurve.generateKeyPair(new SecureRandom()).getKey();

        byte[] copy = new byte[32];
        System.arraycopy(privateKey, 0, copy, 0, 32);
        EllipticCurve.maskPrivateKey(copy);

        Assert.assertArrayEquals(privateKey, copy);
    }
}
