package net.newtownia.ihrszkp;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import javafx.util.Pair;
import org.junit.Assert;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class IHRSZKPTest
{
    private static SecureRandom rnd = new SecureRandom();

    private static byte[] privateKey = null;
    private static Pair<byte[], List<byte[]>> issueData;

    public void setUp()
    {
        if (privateKey != null)
            return;

        privateKey = new byte[32];
        rnd.nextBytes(privateKey);

        List<byte[]> publicKeys = new ArrayList<>();
        publicKeys.add(HexBin.decode("032AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A")); // Basepoint
        publicKeys.add(EllipticCurve.getPublicKey(privateKey).getEncoded(true));

        issueData = IHRSZKP.issue(publicKeys);
    }

    @Test
    public void testIssueData()
    {
        setUp();

        Assert.assertEquals(issueData.getValue().size(), 2);

        // Test weather the mask is properly applied.
        // Does work because the first public key is the base-point of the curve.
        Assert.assertArrayEquals(issueData.getKey(), issueData.getValue().get(0));
    }

    @Test
    public void testProofVerifyDoesWork() throws NoSuchAlgorithmException
    {
        setUp();

        byte[] challenge = new byte[32];
        rnd.nextBytes(challenge);


        Pair<byte[][], byte[][]> proof = IHRSZKP.proof(privateKey, issueData.getValue(), issueData.getKey(), challenge);
        boolean verified = IHRSZKP.verify(proof.getKey(), proof.getValue(), issueData.getValue(), issueData.getKey(), challenge);

        Assert.assertTrue("Validating a valid proof does not work.", verified);
    }

    @Test
    public void testProofAlterVerifyDoesNotWork() throws NoSuchAlgorithmException
    {
        setUp();

        byte[] challenge = new byte[32];
        rnd.nextBytes(challenge);

        Pair<byte[][], byte[][]> proof = IHRSZKP.proof(privateKey, issueData.getValue(), issueData.getKey(), challenge);
        // Alter the data.
        proof.getKey()[0][15] ^= 1;
        boolean verified = IHRSZKP.verify(proof.getKey(), proof.getValue(), issueData.getValue(), issueData.getKey(), challenge);

        Assert.assertFalse("An invalid proof has been accepted as valid.", verified);
    }

    @Test
    public void testProofNotInGroupException() throws NoSuchAlgorithmException
    {
        setUp();

        byte[] challenge = new byte[32];
        rnd.nextBytes(challenge);

        Throwable e = null;

        try
        {
            Pair<byte[][], byte[][]> proof = IHRSZKP.proof(new byte[32], issueData.getValue(), issueData.getKey(), challenge);
        }
        catch (IllegalStateException ex)
        {
            e = ex;
        }
        Assert.assertNotNull("There was no \"NotInGroup\"-Exception.", e);
    }
}
