import sys
import os
import traceback
# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from test_crypto_and_encryption import (
    test_encrypt_decrypt_roundtrip,
    test_decrypt_with_bad_key,
    test_mass_encryption_smoke,
)
from test_database import (
    test_correlation_detects_ransomware,
    test_db_structure_smoke,
)
from test_pe_integration import test_pe_ransomware_demo_smoke, test_pe_demo_without_db_side_effects
from test_network_analysis import test_network_cc_demo_smoke, test_network_attack_demo_smoke
from test_process_monitor_demo import (
    test_heuristic_rule_vssadmin_triggers_alert,
    test_mass_file_operations_triggers_alert,
    test_multiple_file_types_triggers_alert,
)
from test_process_monitor_yara import test_create_suspicious_file_and_pe_and_yara_scan
from test_firewall_rules import test_firewall_rule_drop_ssh, test_firewall_rule_drop_icmp, test_firewall_rule_accept_local_ssh
from test_yara_ransomware import test_yara_rules_compilation_and_db_logging
from test_system import (
    test_imports,
    test_constants,
    test_logging,
    test_database,
    test_components,
    test_firewall_class,
)


def run_test(func):
    try:
        func()
        print(f"[OK] {func.__name__}")
        return True
    except AssertionError as e:
        print(f"[FAIL] {func.__name__}: AssertionError: {e}")
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"[ERROR] {func.__name__}: {e}")
        traceback.print_exc()
        return False


def main():
    tests = [
        test_encrypt_decrypt_roundtrip,
        test_decrypt_with_bad_key,
        test_mass_encryption_smoke,
        test_correlation_detects_ransomware,
        test_db_structure_smoke,
        test_pe_ransomware_demo_smoke,
        test_pe_demo_without_db_side_effects,
        test_network_cc_demo_smoke,
        test_network_attack_demo_smoke,
        test_imports,
        test_constants,
        test_logging,
        test_database,
        test_components,
        test_firewall_class,
        # New demos/tests added
        test_heuristic_rule_vssadmin_triggers_alert,
        test_mass_file_operations_triggers_alert,
        test_multiple_file_types_triggers_alert,
        test_create_suspicious_file_and_pe_and_yara_scan,
        test_firewall_rule_drop_ssh,
        test_firewall_rule_drop_icmp,
        test_firewall_rule_accept_local_ssh,
        test_yara_rules_compilation_and_db_logging,
    ]

    results = [run_test(t) for t in tests]

    if all(results):
        print("\nALL TESTS PASSED")
        sys.exit(0)
    else:
        print("\nSOME TESTS FAILED")
        sys.exit(1)

if __name__ == '__main__':
    main()
