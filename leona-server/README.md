# Leona Server

This directory is intentionally kept as a placeholder.

The Leona hosted API/backend implementation is not open source. It contains decision logic, risk scoring, tenant policy, operational controls, deployment assumptions, and security-sensitive server-side behavior. Publishing that code would weaken the security model by making the server-side bypass surface easier to study.

The public Android SDK remains fully usable by customers when configured with a Leona API key and the Leona hosted endpoints. Final verdicts are produced by the Leona API/backend, not by code shipped in the APK.
