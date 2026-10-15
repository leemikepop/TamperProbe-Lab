package io.leemikepop.tamperprobe.lab.e2e

import org.junit.runner.RunWith
import org.junit.runners.Suite

/**
 * Master E2E Test Suite for TamperProbe SDK.
 * Integrates Tier 1 (Feature Coverage), Tier 2 (Boundary & Corner Cases),
 * Tier 3 (Cross-Feature Combinations), and Tier 4 (Real-World Workloads).
 */
@RunWith(Suite::class)
@Suite.SuiteClasses(
    Tier1FeatureCoverageE2ETest::class,
    Tier2BoundaryCornerCasesE2ETest::class,
    Tier3PairwiseInteractionsE2ETest::class,
    Tier4RealWorldWorkloadsE2ETest::class,
)
class TamperProbeE2ETestSuite
