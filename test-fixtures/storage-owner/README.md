# Storage-owner fixture

This test-only APK gives the package-storage visibility study a second Android
UID. Its exported control provider creates nonce-scoped fixtures only under its
own `Android/data` and `Android/obb` roots, can hold directory file descriptors,
and reports cleanup residuals from the owner UID.

It is not a dependency of `:tamperprobe`, is not published, and contains the
state-changing part of the study. Run it through
`tamperprobe/scripts/run_package_storage_visibility_study.ps1`; production
`PACKAGE_STORAGE_VISIBILITY` probes remain read-only.
