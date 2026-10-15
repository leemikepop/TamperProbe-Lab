package io.leemikepop.tamperprobe.lab.rasp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import io.leemikepop.tamperprobe.lab.lib.core.NativeBridge;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Test;

/**
 * JNI binds performScan by name only, so a parameter added on the native side is not caught at
 * link time: the adapter would pass too few arguments and the engine would read garbage. This test
 * ties the adapter's declaration to the C++ entry point that the SDK shares.
 */
public class NativeBridgeSignatureTest {
    private static final Map<String, Class<?>> JNI_TYPES = Map.of(
            "jobject", Context.class,
            "jstring", String.class,
            "jobjectArray", String[].class,
            "jbyteArray", byte[].class
    );

    @Test
    public void adapterDeclarationMatchesNativeEntryPoint() throws Exception {
        Method performScan = null;
        for (Method method : NativeBridge.class.getDeclaredMethods()) {
            if (method.getName().equals("performScan")) performScan = method;
        }
        assertTrue("NativeBridge.performScan is missing", performScan != null);

        assertEquals(nativeParameterTypes(), Arrays.asList(performScan.getParameterTypes()));
        assertEquals(byte[].class, performScan.getReturnType());
    }

    private static List<Class<?>> nativeParameterTypes() throws Exception {
        Pattern entry = Pattern.compile(
                "Java_io_leemikepop_tamperprobe_lab_lib_core_NativeBridge_performScan\\s*\\(([^)]*)\\)");
        Matcher matcher = entry.matcher(nativeBridgeSource());
        assertTrue("JNI entry point not found in native_bridge.cpp", matcher.find());

        String[] parameters = matcher.group(1).replaceAll("/\\*.*?\\*/", "").split(",");
        List<Class<?>> types = new ArrayList<>();
        // The first two are JNIEnv* and the receiver.
        for (int index = 2; index < parameters.length; index++) {
            String jniType = parameters[index].trim().split("\\s+")[0];
            Class<?> type = JNI_TYPES.get(jniType);
            assertTrue("Unmapped JNI type " + jniType, type != null);
            types.add(type);
        }
        return types;
    }

    private static String nativeBridgeSource() throws Exception {
        Path local = Path.of("../tamperprobe/src/main/cpp/core/native_bridge.cpp");
        Path root = Path.of("tamperprobe/src/main/cpp/core/native_bridge.cpp");
        return new String(Files.readAllBytes(Files.exists(local) ? local : root), StandardCharsets.UTF_8);
    }
}
