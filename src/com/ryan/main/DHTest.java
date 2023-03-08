package com.ryan.main;

import java.security.*;
import javax.crypto.*;

import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class DHTest {

    public static void main(String[] args) throws Exception {
        // Generate Alice's key pair
        KeyPairGenerator aliceKeyPairGen = KeyPairGenerator.getInstance("DH");
        aliceKeyPairGen.initialize(2048);
        KeyPair aliceKeyPair = aliceKeyPairGen.generateKeyPair();

        // Generate Bob's key pair
        KeyPairGenerator bobKeyPairGen = KeyPairGenerator.getInstance("DH");
        bobKeyPairGen.initialize(2048);
        KeyPair bobKeyPair = bobKeyPairGen.generateKeyPair();

        // Alice sends her public key to Bob
        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();

        // Bob sends his public key to Alice
        byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();

        // Alice generates the shared secret key using Bob's public key
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());
        PublicKey bobPubKey = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(bobPubKeyEnc));
        aliceKeyAgree.doPhase(bobPubKey, true);
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();

        // Bob generates the shared secret key using Alice's public key
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKeyPair.getPrivate());
        PublicKey alicePubKey = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(alicePubKeyEnc));
        bobKeyAgree.doPhase(alicePubKey, true);
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();

        // Print the shared secret keys to confirm they are the same
        System.out.println(Arrays.equals(aliceSharedSecret, bobSharedSecret));
    }
}
