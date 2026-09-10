package com.acme.payments.verify;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Owned by the fraud/settlement team, in a different repository from the
 * payments team that signs confirmations.
 *
 * This class was handed the payment-confirmations public key by the
 * payments team when that key was provisioned in KMS. It does not read
 * their repo, does not know their code, and does not get told when they
 * change anything - it only knows the public key it was given, and the
 * algorithm it was told to use with it. That one-way, out-of-band
 * relationship is exactly what a signer-side migration has to preserve.
 */
public class PaymentSignatureVerifier {

    private final PublicKey paymentSigningPublicKey;

    public PaymentSignatureVerifier(byte[] x509EncodedPublicKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.paymentSigningPublicKey = kf.generatePublic(new X509EncodedKeySpec(x509EncodedPublicKey));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not load payment-confirmations public key", e);
        }
    }

    public boolean verifyConfirmation(String paymentReference, long amountCents, byte[] signature) {
        try {
            String payload = paymentReference + ":" + amountCents;
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(paymentSigningPublicKey);
            verifier.update(payload.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            // A GeneralSecurityException here almost always means the signer
            // and this verifier have drifted onto different algorithms.
            return false;
        }
    }
}
