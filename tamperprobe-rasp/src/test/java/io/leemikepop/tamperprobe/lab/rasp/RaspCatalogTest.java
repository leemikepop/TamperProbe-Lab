package io.leemikepop.tamperprobe.lab.rasp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

public class RaspCatalogTest {
    @Test
    public void v1CatalogUsesDetectorLevelSelection() throws Exception {
        String[] selected = RaspCatalog.parse(manifest()).resolve(null);
        assertTrue(selected.length > 0);
        assertTrue(Arrays.asList(selected).contains("BUSYBOX"));
        assertEquals(selected.length, Arrays.stream(selected).distinct().count());
    }

    @Test
    public void researchEditionSelectsEveryDetectorByDefault() throws Exception {
        String[] selected = RaspCatalog.parse(manifest()).resolve(null);
        assertEquals(RaspCatalogExpectation.DETECTOR_COUNT, selected.length);
    }

    @Test(expected = IllegalStateException.class)
    public void legacySchemaIsRejected() throws Exception {
        RaspCatalog.parse(manifest().replaceFirst("\"schemaVersion\": 1", "\"schemaVersion\": 3"));
    }

    @Test(expected = IllegalStateException.class)
    public void unknownPrimaryEvidenceDomainIsRejected() throws Exception {
        RaspCatalog.parse(manifest().replaceFirst(
                "\"primaryEvidenceDomainId\": \"binary-artifact\"",
                "\"primaryEvidenceDomainId\": \"unknown\""
        ));
    }

    @Test
    public void generatedExpectationDescribesTheGeneratedManifest() throws Exception {
        JSONObject root = new JSONObject(manifest());
        JSONArray detections = root.getJSONArray("detections");
        int units = 0;
        for (int index = 0; index < detections.length(); index++) {
            units += detections.getJSONObject(index).getJSONArray("evidenceUnits").length();
        }
        assertEquals(RaspCatalogExpectation.EVIDENCE_DOMAIN_COUNT,
                root.getJSONArray("evidenceDomains").length());
        assertEquals(RaspCatalogExpectation.DETECTOR_COUNT, detections.length());
        assertEquals(RaspCatalogExpectation.EVIDENCE_UNIT_COUNT, units);
        RaspCatalog.verifyDigest(manifestBytes());
    }

    @Test
    public void catalogMissingADetectorIsRejected() throws Exception {
        JSONObject root = new JSONObject(manifest());
        root.getJSONArray("detections").remove(0);

        IllegalStateException error = assertThrows(
                IllegalStateException.class, () -> RaspCatalog.parse(root.toString()));
        assertTrue(error.getMessage().contains("this adapter was built for"));
    }

    @Test
    public void catalogMissingAUnitIsRejected() throws Exception {
        JSONObject root = new JSONObject(manifest());
        assertTrue("fixture needs a detector with a removable unit", removeOneUnit(root));

        IllegalStateException error = assertThrows(
                IllegalStateException.class, () -> RaspCatalog.parse(root.toString()));
        assertTrue(error.getMessage().contains("this adapter was built for"));
    }

    @Test
    public void duplicateDetectorIsRejected() throws Exception {
        JSONObject root = new JSONObject(manifest());
        JSONArray detections = root.getJSONArray("detections");
        detections.getJSONObject(1).put("id", detections.getJSONObject(0).getString("id"));

        assertThrows(IllegalStateException.class, () -> RaspCatalog.parse(root.toString()));
    }

    @Test
    public void alteredCatalogBytesFailTheDigest() throws Exception {
        byte[] altered = (manifest() + " ").getBytes(StandardCharsets.UTF_8);

        assertThrows(IllegalStateException.class, () -> RaspCatalog.verifyDigest(altered));
    }

    /**
     * Drops one unit while keeping a direct unit in the detector's primary domain, so only the
     * unit total can notice the truncation.
     */
    private static boolean removeOneUnit(JSONObject root) throws Exception {
        JSONArray detections = root.getJSONArray("detections");
        for (int index = 0; index < detections.length(); index++) {
            JSONObject detector = detections.getJSONObject(index);
            String primaryDomainId = detector.getString("primaryEvidenceDomainId");
            JSONArray units = detector.getJSONArray("evidenceUnits");
            if (units.length() < 2) continue;
            int primaryUnits = 0;
            for (int unitIndex = 0; unitIndex < units.length(); unitIndex++) {
                if (primaryDomainId.equals(units.getJSONObject(unitIndex).getString("domainId"))) {
                    primaryUnits++;
                }
            }
            for (int unitIndex = 0; unitIndex < units.length(); unitIndex++) {
                boolean isPrimary = primaryDomainId.equals(
                        units.getJSONObject(unitIndex).getString("domainId"));
                if (!isPrimary || primaryUnits > 1) {
                    units.remove(unitIndex);
                    return true;
                }
            }
        }
        return false;
    }

    private static String manifest() throws Exception {
        return new String(manifestBytes(), StandardCharsets.UTF_8);
    }

    private static byte[] manifestBytes() throws Exception {
        Path local = Path.of("../tamperprobe/scripts/generated/detections_manifest.json");
        Path root = Path.of("tamperprobe/scripts/generated/detections_manifest.json");
        return Files.readAllBytes(Files.isRegularFile(local) ? local : root);
    }
}
