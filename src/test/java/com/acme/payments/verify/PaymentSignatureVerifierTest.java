package com.acme.payments.verify;

import org.junit.jupiter.api.Test;

import java.security.*;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class PaymentSignatureVerifierTest {

    /**
     * Stands in for the RSA key the payments team handed us when
     * payment-confirmations was provisioned. In production this arrives
     * out of band (key registry / secure channel), not by reading their
     * source - so this test builds its own copy the same way.
     */
    @Test
    void verifiesAGenuinePaymentConfirmation() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair paymentsTeamKey = kpg.generateKeyPair();

        String payload = "PAY-2002:75000";
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(paymentsTeamKey.getPrivate());
        signer.update(payload.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign();

        PaymentSignatureVerifier verifier =
                new PaymentSignatureVerifier(paymentsTeamKey.getPublic().getEncoded());

        assertTrue(verifier.verifyConfirmation("PAY-2002", 75000, signature));
    }

    @Test
    void rejectsATamperedAmount() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair paymentsTeamKey = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(paymentsTeamKey.getPrivate());
        signer.update("PAY-2002:75000".getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign();

        PaymentSignatureVerifier verifier =
                new PaymentSignatureVerifier(paymentsTeamKey.getPublic().getEncoded());

        assertFalse(verifier.verifyConfirmation("PAY-2002", 999999, signature));
    }
}
