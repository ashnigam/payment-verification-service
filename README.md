# payment-verification-service

Owned by a different team than [`payment-signing-service`](../payment-signing-service). This
service was handed the payment-confirmations public key out of band when that key was
provisioned, and verifies incoming payment confirmations against it.

It has no visibility into the signing service's code and no way to know when that key or its
algorithm changes — which is exactly why a signer-side migration that doesn't account for this
dependency breaks verification silently, in a repository the migration never touched.

See the [migration comparison](../payment-signing-service/MIGRATION_COMPARISON.md) in the signing
service repo for the full story.
