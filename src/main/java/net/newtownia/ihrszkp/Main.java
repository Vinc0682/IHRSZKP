package net.newtownia.ihrszkp;

import javafx.util.Pair;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class Main {

    public static void main(String[] args)
    {
        SecureRandom rnd = new SecureRandom();
        List<byte[]> privateKeys = new ArrayList<>();
        List<byte[]> publicKeys = new ArrayList<>();

        for (int i = 0; i < 10; i += 1)
        {
            Pair<byte[], byte[]> keyPair = EllipticCurve.generateKeyPair(rnd);
            privateKeys.add(keyPair.getKey());
            publicKeys.add(keyPair.getValue());
        }

        Pair<byte[], List<byte[]>> issue = IHRSZKP.issue(publicKeys);

        byte[] challenge = new byte[32];
        new Random().nextBytes(challenge);

        try
        {
            Pair<byte[][], byte[][]> proof = IHRSZKP.proof(privateKeys.get(4),
                    issue.getValue(), issue.getKey(), challenge);

            System.out.println(IHRSZKP.verify(proof.getKey(), proof.getValue(), issue.getValue(), issue.getKey(), challenge));
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
    }
}
