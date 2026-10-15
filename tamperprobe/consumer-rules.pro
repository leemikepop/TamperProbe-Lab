# Native method names are resolved by the exported JNI symbol.
-keep class io.leemikepop.tamperprobe.lab.lib.core.NativeBridge {
    native <methods>;
}

# The opt-in app-zygote carrier is manifest/JNI addressed by its stable name.
-keep class io.leemikepop.tamperprobe.lab.internal.policyoracle.** { *; }

# Native TEE detectors resolve this public-API-only collector by its stable name.
-keep class io.leemikepop.tamperprobe.lab.internal.tee.TeeKeystoreCollector {
    public static java.lang.String collectAttestation(android.content.Context);
    public static java.lang.String checkOversizedChallenge(android.content.Context, int);
    public static java.lang.String collectKeystoreConsistency(android.content.Context);
}

# The wire and detector payload serializers are internal but are part of the
# versioned SDK/native adaptation path. Keep their generated entry points.
-keepattributes InnerClasses,EnclosingMethod,RuntimeVisibleAnnotations,AnnotationDefault
-keep,includedescriptorclasses class io.leemikepop.tamperprobe.lab.internal.**$$serializer { *; }
-keep,includedescriptorclasses class io.leemikepop.tamperprobe.lab.lib.detections.**$$serializer { *; }
-keepclassmembers class io.leemikepop.tamperprobe.lab.internal.** {
    *** Companion;
}
-keepclassmembers class io.leemikepop.tamperprobe.lab.lib.detections.** {
    *** Companion;
}
