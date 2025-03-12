import pytest
from test_results import TestResults
from bgp_fuzz_open_message import BGPFuzzOpenMessage
from bgp_fuzz_notification_message import BGPFuzzNotificationMessage
from bgp_fuzz_update_message import BgpUpdateFuzzer

@pytest.mark.open
@pytest.mark.parametrize("fuzz_method", [
    "fuzz_bgp_open_with_optional_params",
    "fuzz_bgp_open_optional_param_length",
    "fuzz_bgp_open_random_params",
    "fuzz_bgp_open_version_field",
    "fuzz_open_asn",
    "fuzz_open_hold_time",
    "fuzz_open_identifier"
])
def test_fuzz_open_messages(fuzz_method, test_results):
    bgp_test = BGPFuzzOpenMessage('config.json', test_results)
    getattr(bgp_test, fuzz_method)()

@pytest.mark.notification
def test_fuzz_notification(test_results):
    bgp_test = BGPFuzzNotificationMessage('config.json', test_results)
    bgp_test.fuzz_notification()

@pytest.mark.update
@pytest.mark.parametrize("fuzz_method", [
    "update_test_fuzz_withdrawn_routes_length",
    "update_test_fuzz_withdrawn_routes",
    "update_test_fuzz_path_attributes_length",
    "update_test_fuzz_path_attributes",
    "update_test_fuzz_nlri"
])
def test_fuzz_update_messages(fuzz_method, test_results):
    bgp_test = BgpUpdateFuzzer('config.json', test_results)
    getattr(bgp_test, fuzz_method)()
