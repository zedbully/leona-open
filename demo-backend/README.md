# Demo Backend

This directory is intentionally kept as a placeholder.

The demo/customer backend implementation is not open source. Leona's public GitHub repository only ships the Android public integration SDK. Backend examples that can reveal request flow, decision handling, tenant policy, or operational assumptions are kept private for security reasons.

Public SDK users should integrate the Android SDK into their APK and send the returned `BoxId` to their own backend. The customer backend should then query the Leona hosted API/backend for the authoritative verdict.
