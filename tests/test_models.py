from magpie.models import UserStatuses

from tests import runner


@runner.MAGPIE_TEST_UTILS
def test_user_status_value_getter():
    assert UserStatuses.OK.value in UserStatuses.allowed()
    assert UserStatuses.Pending.value in UserStatuses.allowed()
    assert UserStatuses.WebhookError.value in UserStatuses.allowed()
    assert str(UserStatuses.OK.value) in UserStatuses.allowed()
    assert str(UserStatuses.Pending.value) in UserStatuses.allowed()
    assert str(UserStatuses.WebhookError.value) in UserStatuses.allowed()
    assert UserStatuses.OK.name in UserStatuses.allowed()
    assert UserStatuses.Pending.name in UserStatuses.allowed()
    assert UserStatuses.WebhookError.name in UserStatuses.allowed()

    assert UserStatuses.OK in UserStatuses.all()
    assert UserStatuses.Pending in UserStatuses.all()
    assert UserStatuses.WebhookError in UserStatuses.all()
    assert UserStatuses.OK | UserStatuses.Pending | UserStatuses.WebhookError == UserStatuses.all()
    assert UserStatuses.get("ok") == UserStatuses.OK
    assert UserStatuses.get("ok,PENDING") == UserStatuses.OK | UserStatuses.Pending
    assert UserStatuses.get(["ok", "PENDING", "OK"]) == UserStatuses.OK | UserStatuses.Pending
    assert UserStatuses.get("all") == UserStatuses.all()
    assert UserStatuses.get(None) is None


@runner.MAGPIE_TEST_UTILS
def test_user_status_combinations():
    # below order by value is important, sorted from highest to lowest bit
    # no matter the way they are combined using OR operator '|' (enum impl and string repr)
    test_statuses = [UserStatuses.Pending, UserStatuses.WebhookError, UserStatuses.OK]

    # list of class by itself returns all elements
    # in this case, the member iterator is called, which prefers enum's impl to list by member definition
    # this makes it reversed than the HB -> LB in this case
    assert list(UserStatuses) == list(reversed(test_statuses))
    for idx, status in enumerate(reversed(UserStatuses)):
        assert test_statuses[idx] is status

    idx = None

    # iterate items in random order merged by OR, using all items
    merge_status = UserStatuses.Pending | UserStatuses.OK | UserStatuses.WebhookError
    assert len(merge_status) == len(test_statuses)
    for idx, status in enumerate(merge_status):
        assert test_statuses[idx] is status  # iterated value is also an enum member, not plain int
    assert idx == len(test_statuses) - 1
    assert merge_status.value == sum(test_statuses)

    # iterate over partial OR not using all items
    merge_status = UserStatuses.OK | UserStatuses.WebhookError | UserStatuses.OK  # order and duplicate don't care
    test_statuses = [UserStatuses.WebhookError, UserStatuses.OK]  # order important
    assert len(merge_status) == 2
    for idx, status in enumerate(merge_status):
        assert test_statuses[idx] is status  # iterated value is also an enum member, not plain int
    assert idx == 1
    assert merge_status.value == UserStatuses.OK.value + UserStatuses.WebhookError.value

    # iterate still possible over items even if unique one
    merge_status = UserStatuses.Pending
    test_statuses = [UserStatuses.Pending]
    assert len(merge_status) == 1
    for idx, status in enumerate(merge_status):
        assert test_statuses[idx] is status  # iterated value is also an enum member, not plain int
    assert idx == 0
    assert merge_status.value == UserStatuses.Pending.value
