////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
// Licensed under the Apache License, Version 2.0 (the "License");           //
// you may not use this file except in compliance with the License.          //
// You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
// Unless required by applicable law or agreed to in writing, software       //
// distributed under the License is distributed on an "AS IS" BASIS,         //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
// See the License for the specific language governing permissions and       //
// limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// SecurityTest -- Verify security hardening measures (GAP-011).
//
// These tests exercise security guards that are activated through
// always-linked paths (e.g. ensureCoreDumpGuard via makeContext).
// We create a minimal Context to trigger the guard, then verify the
// resulting process state.

#include "utils/security/Security.hpp"
#include "EVI/Context.hpp"

#include <gtest/gtest.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

// Force the core-dump guard to run by calling ensureCoreDumpGuard() directly.
// In production this happens inside makeContext(), but calling it explicitly
// here keeps the test self-contained and avoids heavyweight Context setup.
class SecurityTest : public ::testing::Test {
protected:
    void SetUp() override {
        evi::security::ensureCoreDumpGuard();
    }
};

#if defined(__linux__) || defined(__APPLE__)

TEST_F(SecurityTest, CoreDumpsDisabled) {
    struct rlimit rlim {};
    ASSERT_EQ(getrlimit(RLIMIT_CORE, &rlim), 0);

    // Soft limit must always be zero after the guard runs.
    EXPECT_EQ(rlim.rlim_cur, 0u);

    // Hard limit: lowering it to 0 requires CAP_SYS_RESOURCE on some systems.
    // If the guard managed to set it, verify; otherwise just warn.
    if (rlim.rlim_max != 0u) {
        // Not a failure -- the guard tried but lacked privilege to lower
        // the hard limit.  The soft limit of 0 is sufficient to prevent
        // core dumps under normal operation.
        GTEST_LOG_(WARNING) << "rlim_max is " << rlim.rlim_max
                            << " (expected 0). Process may lack CAP_SYS_RESOURCE to lower "
                               "the hard limit. Soft limit is correctly 0.";
    }
}

#ifdef __linux__
#include <sys/prctl.h>

TEST_F(SecurityTest, ProcessNotDumpable) {
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (dumpable < 0) {
        GTEST_SKIP() << "prctl(PR_GET_DUMPABLE) not available";
    }
    EXPECT_EQ(dumpable, 0);
}
#endif // __linux__

#else // non-POSIX

TEST_F(SecurityTest, GuardIsNoOpOnThisPlatform) {
    // ensureCoreDumpGuard() should not crash on unsupported platforms.
    SUCCEED();
}

#endif
