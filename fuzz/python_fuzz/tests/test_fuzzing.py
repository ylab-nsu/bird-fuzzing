import pytest
from app.test_results import ResultsContainer
from app.bgp.bgp_fuzz_open_message import BGPFuzzOpenMessage
from app.bgp.bgp_fuzz_notification_message import BGPFuzzNotificationMessage
from app.bgp.bgp_fuzz_update_message import BgpUpdateFuzzer
from app.bfd.bfd import BFDFuzzTest
from app.rip.rip import RIPFuzzTest


@pytest.mark.bgpOpen
@pytest.mark.parametrize(
    "fuzz_method",
    [
        "fuzz_bgp_open_with_optional_params",
        "fuzz_bgp_open_optional_param_length",
        "fuzz_bgp_open_random_params",
        "fuzz_bgp_open_version_field",
        "fuzz_open_asn",
        "fuzz_open_hold_time",
        "fuzz_open_identifier",
    ],
)
def test_fuzz_open_messages(fuzz_method, max_tests, test_results):
    bgp_test = BGPFuzzOpenMessage("config.json", test_results, max_tests=max_tests)
    getattr(bgp_test, fuzz_method)()


@pytest.mark.bgpNotification
def test_fuzz_notification(max_tests, test_results):
    bgp_test = BGPFuzzNotificationMessage(
        "config.json", test_results, max_tests=max_tests
    )
    bgp_test.fuzz_notification()


@pytest.mark.bgpUpdate
@pytest.mark.parametrize(
    "fuzz_method",
    [
        "update_test_fuzz_withdrawn_routes_length",
        "update_test_fuzz_withdrawn_routes",
        "update_test_fuzz_path_attributes_length",
        "update_test_fuzz_path_attributes",
        "update_test_fuzz_nlri",
    ],
)
def test_fuzz_update_messages(fuzz_method, max_tests, test_results):
    bgp_test = BgpUpdateFuzzer("config.json", test_results, max_tests=max_tests)
    getattr(bgp_test, fuzz_method)()


@pytest.mark.bfd
@pytest.mark.parametrize(
    "fuzz_method",
    [
        "fuzz_version_diag",
        "fuzz_state_flags",
        "fuzz_detect_mult",
        "fuzz_length",
        "fuzz_my_discriminator",
        "fuzz_your_discriminator",
        "fuzz_intervals",
        "fuzz_all_fields",
    ],
)
def test_fuzz_bfd_messages(fuzz_method, max_tests, test_results):
    bfd_test = BFDFuzzTest("config.json", max_tests=max_tests)
    getattr(bfd_test, fuzz_method)()

@pytest.mark.rip
@pytest.mark.parametrize(
    "fuzz_method",
    [
        "fuzz_authentication",
        "fuzz_metric",
        "fuzz_command_version",
        "fuzz_route_entries",
        "fuzz_malformed_packets",
        "fuzz_afi",
        "fuzz_ip_address",
        "fuzz_mask",
    ],
)
def test_fuzz_rip_messages(fuzz_method, max_tests, test_results):
    rip_test = RIPFuzzTest(config_file="config.json", max_tests=max_tests)
    getattr(rip_test, fuzz_method)()