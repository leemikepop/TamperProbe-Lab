package io.leemikepop.tamperprobe.lab.rasp;

import android.content.Context;
import android.os.Bundle;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class RaspCatalog {
    private static final String ASSET_PATH = "tamperprobe/detections_manifest.json";
    private static final String ENABLED_KEY = "io.leemikepop.tamperprobe.lab.ENABLED_DETECTIONS";
    private static final String DISABLED_KEY = "io.leemikepop.tamperprobe.lab.DISABLED_DETECTIONS";

    private final List<Entry> entries;

    private RaspCatalog(List<Entry> entries) {
        this.entries = entries;
    }

    static RaspCatalog load(Context context) throws Exception {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        try (InputStream input = context.getAssets().open(ASSET_PATH)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) content.write(buffer, 0, read);
        }

        byte[] bytes = content.toByteArray();
        verifyDigest(bytes);
        return parse(new String(bytes, StandardCharsets.UTF_8));
    }

    /**
     * Rejects a bundled catalog that is not byte-for-byte the one this adapter was built with.
     * The expected digest is generated from the manifest at build time, so it cannot go stale.
     */
    static void verifyDigest(byte[] content) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte value : digest) hex.append(String.format("%02x", value & 0xff));
        if (!RaspCatalogExpectation.MANIFEST_SHA256.equals(hex.toString())) {
            throw new IllegalStateException(
                    "Bundled detector catalog does not match the catalog this adapter was built with");
        }
    }

    static RaspCatalog parse(String content) throws Exception {
        JSONObject root = new JSONObject(content);
        int schemaVersion = root.optInt("schemaVersion", 0);
        if (schemaVersion != 1
                || !"1.0".equals(root.optString("catalogVersion"))
                || root.optInt("evidenceContractVersion", 0) != 1) {
            throw new IllegalStateException("Unsupported detector catalog schema");
        }

        Set<String> domainIds = new HashSet<>();
        JSONArray evidenceDomains = root.getJSONArray("evidenceDomains");
        for (int index = 0; index < evidenceDomains.length(); index++) {
            JSONObject domain = evidenceDomains.getJSONObject(index);
            domainIds.add(domain.getString("id"));
            if (domain.getString("title").isEmpty()
                    || domain.getString("shortTitle").isEmpty()
                    || domain.getString("description").isEmpty()) {
                throw new IllegalStateException("Evidence Domain metadata is incomplete");
            }
        }
        if (domainIds.size() != evidenceDomains.length()) {
            throw new IllegalStateException("Catalog contains duplicate Evidence Domain IDs");
        }
        if (evidenceDomains.length() != RaspCatalogExpectation.EVIDENCE_DOMAIN_COUNT) {
            throw new IllegalStateException("Catalog has " + evidenceDomains.length()
                    + " Evidence Domains; this adapter was built for "
                    + RaspCatalogExpectation.EVIDENCE_DOMAIN_COUNT);
        }

        List<Entry> entries = new ArrayList<>();
        Set<String> detectorIds = new HashSet<>();
        JSONArray detections = root.getJSONArray("detections");
        int unitCount = 0;
        for (int index = 0; index < detections.length(); index++) {
            JSONObject item = detections.getJSONObject(index);
            if (!detectorIds.add(item.getString("id"))) {
                throw new IllegalStateException("Duplicate detector ID: " + item.getString("id"));
            }
            String primaryDomainId = item.getString("primaryEvidenceDomainId");
            if (!domainIds.contains(primaryDomainId) || item.getInt("payloadSchemaVersion") != 1) {
                throw new IllegalStateException("Unknown primary Evidence Domain: " + primaryDomainId);
            }
            boolean primaryRepresented = false;
            JSONArray evidenceUnits = item.getJSONArray("evidenceUnits");
            unitCount += evidenceUnits.length();
            for (int unitIndex = 0; unitIndex < evidenceUnits.length(); unitIndex++) {
                String unitDomainId = evidenceUnits.getJSONObject(unitIndex).getString("domainId");
                if (!domainIds.contains(unitDomainId)) {
                    throw new IllegalStateException("Unknown unit Evidence Domain: " + unitDomainId);
                }
                if (primaryDomainId.equals(unitDomainId)) {
                    primaryRepresented = true;
                }
            }
            if (!primaryRepresented) {
                throw new IllegalStateException("Detector primary Evidence Domain has no direct unit");
            }
            entries.add(new Entry(item.getString("id")));
        }
        // Expected counts are generated from the manifest at build time (see
        // generateRaspCatalogExpectation); a truncated or edited catalog no longer matches them.
        if (entries.size() != RaspCatalogExpectation.DETECTOR_COUNT
                || unitCount != RaspCatalogExpectation.EVIDENCE_UNIT_COUNT) {
            throw new IllegalStateException("Catalog has " + entries.size() + " detectors and "
                    + unitCount + " units; this adapter was built for "
                    + RaspCatalogExpectation.DETECTOR_COUNT + " and "
                    + RaspCatalogExpectation.EVIDENCE_UNIT_COUNT);
        }
        Collections.sort(entries, (left, right) -> left.id.compareTo(right.id));
        return new RaspCatalog(entries);
    }

    String[] resolve(Bundle metadata) {
        Set<String> known = new HashSet<>();
        for (Entry entry : entries) known.add(entry.id);

        String enabled = metadata == null ? null : metadata.getString(ENABLED_KEY);
        if (enabled != null && !enabled.trim().isEmpty()) {
            return validate(parseIds(enabled), known);
        }

        Set<String> disabled = metadata == null
                ? Collections.emptySet()
                : parseIds(metadata.getString(DISABLED_KEY, ""));
        validateKnown(disabled, known);

        // The research edition has no maturity tiers or default selection: every detector runs
        // unless DISABLED_DETECTIONS removes it.
        List<String> selected = new ArrayList<>();
        for (Entry entry : entries) {
            if (!disabled.contains(entry.id)) selected.add(entry.id);
        }
        if (selected.isEmpty()) throw new IllegalArgumentException("RASP detector selection is empty");
        return selected.toArray(new String[0]);
    }

    private static Set<String> parseIds(String raw) {
        Set<String> ids = new LinkedHashSet<>();
        if (raw == null) return ids;
        for (String part : raw.split(",")) {
            String id = part.trim();
            if (!id.isEmpty()) ids.add(id);
        }
        return ids;
    }

    private static String[] validate(Set<String> ids, Set<String> known) {
        if (ids.isEmpty()) throw new IllegalArgumentException("RASP detector selection is empty");
        validateKnown(ids, known);
        List<String> sorted = new ArrayList<>(ids);
        Collections.sort(sorted);
        return sorted.toArray(new String[0]);
    }

    private static void validateKnown(Set<String> ids, Set<String> known) {
        Set<String> unknown = new LinkedHashSet<>(ids);
        unknown.removeAll(known);
        if (!unknown.isEmpty()) throw new IllegalArgumentException("Unknown detector IDs: " + unknown);
    }

    private static final class Entry {
        final String id;

        Entry(String id) {
            this.id = id;
        }
    }
}
