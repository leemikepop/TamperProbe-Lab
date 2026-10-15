package io.leemikepop.tamperprobe.lab.internal.policyoracle;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class PolicyOraclePayloads {
    static final int MAX_PAYLOAD_BYTES = 64 * 1024;

    private static volatile byte[] preloadedSnapshot;

    private PolicyOraclePayloads() {}

    static void setPreloadedSnapshot(byte[] snapshot) {
        preloadedSnapshot = snapshot == null ? null : Arrays.copyOf(snapshot, snapshot.length);
    }

    static byte[] getPreloadedSnapshot() {
        byte[] snapshot = preloadedSnapshot;
        return snapshot == null ? null : Arrays.copyOf(snapshot, snapshot.length);
    }

    static byte[] failure(String message) {
        String safeMessage = message == null || message.trim().isEmpty()
                ? "Policy-oracle snapshot is unavailable."
                : message.trim();
        String json = "{\"schemaVersion\":2,\"collectionFailure\":{" +
                "\"source\":\"carrier\",\"message\":\"" + escapeJson(safeMessage) + "\"}}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static String escapeJson(String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\': result.append("\\\\"); break;
                case '"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        result.append(String.format("\\u%04x", (int) character));
                    } else {
                        result.append(character);
                    }
            }
        }
        return result.toString();
    }
}
