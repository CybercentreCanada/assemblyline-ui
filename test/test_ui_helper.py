
from unittest.mock import patch
from assemblyline_ui.helper.user import (
    check_async_submission_quota,
    check_submission_quota,
    increase_daily_submission_quota,
    release_daily_submission_quota,
)
import assemblyline_ui.helper.user
from assemblyline.remote.datatypes.user_quota_tracker import UserQuotaTracker
from assemblyline.remote.datatypes.daily_quota_tracker import DailyQuotaTracker


# noinspection PyUnusedLocal
def test_increase_daily_submission_quota(config, redis_connection):
    config.ui.enforce_quota = True
    config.ui.default_quotas.daily_submissions = 5
    assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER = DailyQuotaTracker(redis_connection)
    assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER._counter_name = lambda a, b: "test-counter-1"
    daily_quota_tracker = assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER
    assemblyline_ui.helper.user.flask_session = {}

    quota_user = "test-u1"
    test_user1 = {"uname": quota_user,
                  "submission_daily_quota": 3}

    daily_quota_tracker.reset_submission(quota_user)
    # user's submission_daily_quota should be the max quota for the day
    for i in range(3):
        increase_daily_submission_quota(test_user1)
        assert daily_quota_tracker.get_submission(quota_user) == i + 1

    # should return error message when daily submission quota exceeds
    msg = increase_daily_submission_quota(test_user1)

    assert f"You've reached your daily maximum submission quota of {test_user1['submission_daily_quota']}" in msg
    # assert that user's usage is not increased when there is an error
    assert daily_quota_tracker.get_submission(quota_user) == test_user1["submission_daily_quota"]

    # test release daily quota, which should subtract 1 from quota tracked.
    for i in range(3):
        release_daily_submission_quota(test_user1)
        assert daily_quota_tracker.get_submission(quota_user) == (2 - i)
    daily_quota_tracker.reset_submission(quota_user)

    quota_user = "test-u2"
    test_user2 = {
        "uname": quota_user
    }

    # when user's daily submission_daily_quota is not set, use the default UI config quota
    for i in range(config.ui.default_quotas.daily_submissions):
        increase_daily_submission_quota(test_user2)
        assert daily_quota_tracker.get_submission(quota_user) == i + 1

    msg = increase_daily_submission_quota(test_user2)
    assert f"You've reached your daily maximum submission quota of {config.ui.default_quotas.daily_submissions}" in msg
    assert daily_quota_tracker.get_submission(quota_user) == config.ui.default_quotas.daily_submissions
    daily_quota_tracker.reset_submission(quota_user)

    # do not enforce quota when ui quota setting is false
    quota_user = "test-u3"
    config.ui.enforce_quota = False
    config.ui.default_quotas.daily_submissions = 3
    test_user3 = {"uname": quota_user, "submission_daily_quota": 2}

    # user can submit more than quota numbers
    for i in range(4):
        msg = increase_daily_submission_quota(test_user3)

    # quota is not tracked when enforce_quota is false
    assert daily_quota_tracker.get_submission(quota_user) == 0
    assert msg == None

    # do not enforce quota if no user daily submission quota set
    # and UI doesn't have default submission quota set or the value is 0
    quota_user = "test-u4"
    config.ui.enforce_quota = True
    config.ui.default_quotas.daily_submissions = 0
    test_user4 = {"uname": quota_user}

    # user can submit more than quota numbers
    for i in range(4):
        msg = increase_daily_submission_quota(test_user4)

    # quota is not tracked
    assert daily_quota_tracker.get_submission(quota_user) == 0
    assert msg == None
    daily_quota_tracker.reset_submission(quota_user)


def test_check_submission_quota(config, redis_connection):
    config.ui.enforce_quota = True
    assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER = DailyQuotaTracker(redis_connection)
    assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER._counter_name = lambda a, b: "test-counter-2"
    daily_quota_tracker = assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER
    assemblyline_ui.helper.user.SUBMISSION_TRACKER = UserQuotaTracker('test-quota', timeout=500, redis=redis_connection)
    submission_tracker = assemblyline_ui.helper.user.SUBMISSION_TRACKER

    assemblyline_ui.helper.user.flask_session = {}
    flask_session = assemblyline_ui.helper.user.flask_session

    quota_user = "test-u1"
    test_user1 = {"uname": quota_user,
                  "submission_daily_quota": 3}

    daily_quota_tracker.reset_submission(quota_user)
    submission_tracker.reset(quota_user)
    for i in range(3):
        check_submission_quota(test_user1)
        assert daily_quota_tracker.get_submission(quota_user) == i + 1
        assert flask_session["remaining_quota_submission"] == 2 - i

    # should return error message when daily submission quota exceeds
    msg = check_submission_quota(test_user1)

    assert f"daily maximum submission quota of {test_user1['submission_daily_quota']}" in msg
    # assert that user's usage is not increased when there is an error
    assert daily_quota_tracker.get_submission(quota_user) == test_user1["submission_daily_quota"]
    # assert flask session is keeping track of the remaining quota
    assert flask_session["remaining_quota_submission"] == 0
    daily_quota_tracker.reset_submission(quota_user)
    submission_tracker.reset(quota_user)

    # test errors when concurrent submission quota is set in ui config
    quota_user = "test-u2"
    config.ui.default_quotas.concurrent_submissions = 3
    test_user2 = {"uname": quota_user,
                  "submission_daily_quota": 4}

    for i in range(3):
        check_submission_quota(test_user2)

    # this creates the 4th concurrent submission, which should return error text
    msg = check_submission_quota(test_user2)
    assert f"exceeded your maximum concurrent submission quota of 3" in msg

    # assert that the error does not cause the daily quota and concurrent quota to go up
    assert daily_quota_tracker.get_submission(quota_user) == 3
    assert flask_session["remaining_quota_submission"] == 0
    assert submission_tracker.get_count(quota_user) == 3
    daily_quota_tracker.reset_submission(quota_user)
    submission_tracker.reset(quota_user)

    # test errors when concurrent submission quota is set by user
    quota_user = "test-u3"
    test_user3 = {"uname": quota_user,
                  "submission_daily_quota": 4,
                  "submission_quota": 3}

    for i in range(3):
        check_submission_quota(test_user3)

    # this creates the 4th concurrent submission, which should return error text
    msg = check_submission_quota(test_user3)
    assert f"exceeded your maximum concurrent submission quota of 3" in msg

    # assert that the error does not cause the daily quota and concurrent quota to go up
    assert daily_quota_tracker.get_submission(quota_user) == 3
    assert flask_session["remaining_quota_submission"] == 0
    assert submission_tracker.get_count(quota_user) == 3
    daily_quota_tracker.reset_submission(quota_user)
    submission_tracker.reset(quota_user)

def test_check_async_submission_quota(config, redis_connection):
    config.ui.enforce_quota = True
    assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER = DailyQuotaTracker(redis_connection)
    assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER._counter_name = lambda a, b: "test-counter-3"
    daily_quota_tracker = assemblyline_ui.helper.user.DAILY_QUOTA_TRACKER
    assemblyline_ui.helper.user.ASYNC_SUBMISSION_TRACKER = UserQuotaTracker('test-async-quota', timeout=500, redis=redis_connection)
    async_submission_tracker = assemblyline_ui.helper.user.ASYNC_SUBMISSION_TRACKER

    assemblyline_ui.helper.user.flask_session = {}

    quota_user = "test-u1"
    test_user1 = {"uname": quota_user,
                  "submission_daily_quota": 3}

    daily_quota_tracker.reset_submission(quota_user)
    async_submission_tracker.reset(quota_user)
    for i in range(3):
        check_async_submission_quota(test_user1)
        assert daily_quota_tracker.get_submission(quota_user) == i + 1

    # should return error message when daily submission quota exceeds
    msg = check_async_submission_quota(test_user1)

    assert f"daily maximum submission quota of {test_user1['submission_daily_quota']}" in msg
    # assert that user's usage is not increased when there is an error
    assert daily_quota_tracker.get_submission(quota_user) == test_user1["submission_daily_quota"]
    daily_quota_tracker.reset_submission(quota_user)
    async_submission_tracker.reset(quota_user)

    # test errors when concurrent submission quota is set in ui config
    quota_user = "test-u2"
    config.ui.default_quotas.concurrent_async_submissions = 3
    test_user2 = {"uname": quota_user,
                  "submission_daily_quota": 4}

    for i in range(3):
        check_async_submission_quota(test_user2)

    # this creates the 4th concurrent submission, which should return error text
    msg = check_async_submission_quota(test_user2)
    assert f"maximum async concurrent submission quota of 3" in msg

    # assert that the error does not cause the daily quota and concurrent quota to go up
    assert daily_quota_tracker.get_submission(quota_user) == 3
    # assert that user's concurrent submission does not increase when there is an error
    assert async_submission_tracker.get_count(quota_user) == 3
    daily_quota_tracker.reset_submission(quota_user)
    async_submission_tracker.reset(quota_user)

    # test errors when concurrent submission quota is set by user
    quota_user = "test-u3"
    test_user3 = {"uname": quota_user,
                  "submission_daily_quota": 4,
                  "submission_async_quota": 3}

    for i in range(3):
        check_async_submission_quota(test_user3)

    # this creates the 4th concurrent submission, which should return error text
    msg = check_async_submission_quota(test_user3)
    assert f"maximum async concurrent submission quota of 3" in msg

    # assert that the error does not cause the daily quota and concurrent quota to go up
    assert daily_quota_tracker.get_submission(quota_user) == 3
    # assert that user's concurrent submission does not increase when there is an error
    assert async_submission_tracker.get_count(quota_user) == 3
    daily_quota_tracker.reset_submission(quota_user)
    async_submission_tracker.reset(quota_user)
