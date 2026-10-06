package com.acme.payments.verify;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KmsInvalidSignatureException;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.VerifyRequest;

import java.nio.charset.StandardCharsets;

/**
 * Verifies payment confirmations signed by the payments team's KMS key.
 *
 * The check happens inside KMS: this service never holds the key, public or
 * private. Both teams name the same KMS key.
 */
public class KmsPaymentVerifier {

    private final KmsClient kms;

    public KmsPaymentVerifier(KmsClient kms) {
        this.kms = kms;
    }

    public boolean verifyConfirmation(String paymentReference, long amountCents, byte[] signature) {
        String payload = paymentReference + ":" + amountCents;
        VerifyRequest request = VerifyRequest.builder()
                .keyId("arn:aws:kms:us-west-2:826420459991:key/d49c342a-1e59-4f75-951d-db15a871b8d2")
                .message(SdkBytes.fromByteArray(payload.getBytes(StandardCharsets.UTF_8)))
                .messageType(MessageType.RAW)
                .signature(SdkBytes.fromByteArray(signature))
                .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                .build();
        try {
            return kms.verify(request).signatureValid();
        } catch (KmsInvalidSignatureException e) {
            // KMS reports a signature that does not match as an error, not as false.
            return false;
        }
    }
}
