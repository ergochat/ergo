# Changelog
All notable changes to webpush-go will be documented in this file.

## [2.0.0] - 2025-01-16

* Update the `Keys` struct definition to store `Auth` as `[16]byte` and `P256dh` as `*ecdh.PublicKey`
    * `Keys` can no longer be compared with `==`; use `(*Keys.Equal)` instead
    * The JSON representation has not changed and is backwards and forwards compatible with v1
    * `DecodeSubscriptionKeys` is a helper to decode base64-encoded auth and p256dh parameters into a `Keys`, with validation
* Update the `VAPIDKeys` struct to contain a `(*ecdsa.PrivateKey)`
    * `VAPIDKeys` can no longer be compared with `==`; use `(*VAPIDKeys).Equal` instead
    * The JSON representation is now a JSON string containing the PEM of the PKCS8-encoded private key
    * To parse the legacy representation (raw bytes of the private key encoded in base64), use `DecodeLegacyVAPIDPrivateKey`
* Renamed `SendNotificationWithContext` to `SendNotification`, removing the earlier `SendNotification` API. (Pass `context.Background()` as the context to restore the former behavior.)
