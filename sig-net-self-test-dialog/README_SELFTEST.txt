//==============================================================================
// Sig-Net Library Self-Test Framework
//==============================================================================
//
// OVERVIEW
// --------
// The Sig-Net library includes an embedded self-test framework that validates
// all major components (crypto, CoAP, TLV, security, packet building). The
// framework is designed to be called from any application module, with a
// reusable VCL dialog for displaying results.
//
// ARCHITECTURE
// -----------
//
// 1. Library Self-Tests (sig-net-selftest.hpp/cpp)
//
//    The core test engine resides in the library itself. This enables:
//    - Standalone testing without VCL dependencies
//    - Embedding tests in headless/embedded environments
//    - Reuse across multiple C++Builder modules
//
//    Key components:
//    - TestSuiteResults: Structure holding all test results
//    - RunAllTests(): Main test runner
//    - Individual test categories (crypto, CoAP, TLV, security, send)
//
// 2. VCL Test Dialog (sig-net-self-test-dialog/)
//
//    A reusable VCL form component that displays test results in a grid:
//    - SelfTestResultsForm.h/cpp/dfm
//    - Dynamically creates UI components
//    - Color-codes pass/fail results (green/red)
//    - Supports copying results to clipboard
//
// USAGE EXAMPLES
// ---------------
//
// Example 1: Run tests and display results in a dialog
// =====================================================
//
//   #include "SelfTestResultsForm.h"
//
//   void RunSelfTests() {
//       TSelfTestResultsForm* form = new TSelfTestResultsForm(Application);
//       form->ShowModal();
//       delete form;
//   }
//
// Example 2: Programmatic test access (no VCL)
// ============================================
//
//   #include "sig-net.hpp"
//
//   SigNet::SelfTest::TestSuiteResults results;
//   int32_t test_status = SigNet::SelfTest::RunAllTests(results);
//
//   for (size_t i = 0; i < results.test_count; i++) {
//       printf("[%s] %s: %s\n",
//              results.tests[i].passed ? "PASS" : "FAIL",
//              results.tests[i].name,
//              results.tests[i].error_message);
//   }
//
// Example 3: Call from startup or menu
// =====================================
//
//   // In MainForm.cpp
//   #include "SelfTestResultsForm.h"
//
//   void __fastcall TMainForm::MenuItemSelfTestClick(TObject* Sender) {
//       TSelfTestResultsForm* dialog = new TSelfTestResultsForm(this);
//       dialog->ShowModal();
//       delete dialog;
//   }
//
// TEST CATEGORIES
// ----------------
//
// 1. Crypto Module Tests (8 tests)
//    - K0 Derivation: Verify sender key derivation from K0
//    - HMAC-SHA256: RFC 4868 known test vector
//    - Passphrase Validation: Valid complex, too short, invalid runs, invalid sequential
//    - Random Passphrase Generation: Uniqueness, entropy, validation
//    - CRC-16 Calculation: Known vector for K0 validation
//
// 2. CoAP Module Tests (4 tests)
//    - Option Encoding: Inline delta, extended 8-bit delta
//    - URI Path Encoding: Path-to-string conversion
//    - CoAP Header Construction: Basic header validity
//
// 3. TLV Module Tests (3 tests)
//    - TID_LEVEL Encoding: Single TLV encoding
//    - DMX Payload Building: Full DMX payload composition
//    - Announce Payload Building: Multi-TLV announce packet
//
// 4. Security Module Tests (1 test)
//    - HMAC Building: Signature generation
//
// 5. Send Module Tests (4 tests)
//    - Multicast Address Calculation: Universe to IP mapping
//    - Sequence Increment: Basic sequence management
//    - Sequence Rollover: 32-bit wrap-around
//    - DMX Packet Building: Complete packet assembly integration test
//
// Total: 20 tests across all modules
//
// INTEGRATION WITH MODULES
// -------------------------
//
// Each module being tested is imported via #include:
//
//   - sig-net-crypto.hpp: K0 derivation, HMAC, passphrase ops, CRC-16
//   - sig-net-coap.hpp: Option encoding, URI building
//   - sig-net-tlv.hpp: TLV encoding, payload composition
//   - sig-net-security.hpp: HMAC building
//   - sig-net-send.hpp: Packet building, multicast calculation, sequencing
//
// This means tests will catch:
//   - API signature changes
//   - Return value modifications
//   - Encoding algorithm drift
//   - Integration failures between modules
//
// EXTENDING THE TESTS
// --------------------
//
// To add new tests:
//
// 1. Add test function to a category in sig-net-selftest.cpp:
//
//    void TestNewModule(TestSuiteResults& results) {
//        // Test implementation
//        bool passed = /* test condition */;
//        AddTestResult(results, "New Module: Test Description", passed, error_msg);
//    }
//
// 2. Call it from RunAllTests():
//
//    TestNewModule(results);
//
// 3. Recompile library
//
// COMPLIANCE & KNOWN VECTORS
// ----------------------------
//
// Tests use official test vectors where possible:
//   - HMAC-SHA256: RFC 4868 (IETF standard)
//   - Passphrase rules: Sig-Net Spec v0.12 Section 7.2.3
//   - CoAP encoding: RFC 7252 (IETF standard)
//   - K0 test vector: Project notes (entropy distribution proven)
//
// DEPLOYMENT CHECKLIST
// --------------------
//
// Before releasing:
// [ ] Run tests in debug build  - all green
// [ ] Run tests in release build - all green
// [ ] Run tests on multiple platforms (if applicable)
// [ ] Document any new tests in this file
// [ ] Add test results to release notes (pass count, test coverage %)
//
// TROUBLESHOOTING
// ----------------
//
// Q: Tests fail with "HMAC mismatch" error
// A: Verify Windows BCrypt is linked (ws2_32.lib, bcrypt.lib in project)
//
// Q: Random passphrase generation fails validation
// A: Check PASSPHRASE_GEN_* character sets haven't been modified
//
// Q: Dialog won't compile
// A: Ensure SelfTestResultsForm.dpk package is in project, all VCL headers present
//
// Q: DMX packet building integration test fails
// A: Check sig-net-send.cpp BuildDMXPacket hasn't changed API signature
//
// MAINTENANCE
// -----------
//
// When making API changes to library modules:
// 1. Update self-tests to match new API
// 2. Update known vectors if algorithm changes
// 3. Run full test suite before committing
// 4. Document changes in this README
//
//==============================================================================
