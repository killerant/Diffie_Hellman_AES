package com.ryan.main;

import java.security.*;
import java.util.Base64;

public class ISeries {
    private PublicKey iSeriesPublicKey;
    private PrivateKey iSeriesPrivateKey;

    public ISeries() {
        try {

            // Generate a new key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get the public and private keys from the key pair
            iSeriesPublicKey = keyPair.getPublic();
            iSeriesPrivateKey = keyPair.getPrivate();
            System.out.println("iSeries Object Private Key Format:: " + iSeriesPrivateKey.getFormat());
            System.out.println("iSeries Object Public Key Format:: " + iSeriesPublicKey.getFormat());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public PublicKey getISeriesPublicKey() {
        return iSeriesPublicKey;
    }

    public PrivateKey getISeriesPrivateKey() {
        return iSeriesPrivateKey;
    }

    public String getStringISeriesPublicKey() {
        return Base64.getEncoder().encodeToString(iSeriesPublicKey.getEncoded());
    }

    public String getStringISeriesPrivateKey() {
        return Base64.getEncoder().encodeToString(iSeriesPrivateKey.getEncoded());
    }
}
