package io.leemikepop.tamperprobe.lab.internal.policyoracle;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class SelinuxPolicyOracleCarrierManagerTest {
    @Test
    public void carrierAvailabilityExcludesAndroid10() {
        assertFalse(SelinuxPolicyOracleCarrierManager.isCarrierSupportedOnApi(29));
        assertTrue(SelinuxPolicyOracleCarrierManager.isCarrierSupportedOnApi(30));
    }
}
