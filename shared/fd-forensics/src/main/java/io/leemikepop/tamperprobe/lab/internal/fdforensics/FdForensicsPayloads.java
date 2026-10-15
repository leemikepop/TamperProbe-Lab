package io.leemikepop.tamperprobe.lab.internal.fdforensics;

import java.nio.charset.StandardCharsets;

final class FdForensicsPayloads {
    static final int MAX_PAYLOAD_BYTES = 64 * 1024;

    private FdForensicsPayloads() {}

    static byte[] failure(String message) {
        String safeMessage = message == null || message.trim().isEmpty()
                ? "Descriptor-forensics snapshot is unavailable."
                : message.trim();
        String json = "{\"schemaVersion\":1,\"collectionFailure\":{" +
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
