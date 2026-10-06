package com.acme.payments.verify;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;

/**
 * Verifies payment confirmations signed by the payments team's KMS key.
 *
 * Only the public half of the key is ever fetched. The signing team owns the
 * private key and this team never sees it; both teams name the same KMS key.
 */
public class KmsPaymentVerifier {

    // Same demo key the payments team signs with (alias/qryptive-demo-signer).
    static final String PAYMENT_CONFIRMATION_KEY_ARN =
            "arn:aws:kms:us-west-2:826420459991:key/d49c342a-1e59-4f75-951d-db15a871b8d2";

    private final PaymentSignatureVerifier verifier;

    public KmsPaymentVerifier(KmsClient kms) {
        byte[] publicKey = kms.getPublicKey(
                GetPublicKeyRequest.builder().keyId(PAYMENT_CONFIRMATION_KEY_ARN).build())
                .publicKey().asByteArray();
        this.verifier = new PaymentSignatureVerifier(publicKey);
    }

    public boolean verifyConfirmation(String paymentReference, long amountCents, byte[] signature) {
        return verifier.verifyConfirmation(paymentReference, amountCents, signature);
    }
}
