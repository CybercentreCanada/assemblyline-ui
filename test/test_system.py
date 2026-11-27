import time

import pytest
from assemblyline.common import forge
from assemblyline.common.constants import DISPATCH_TASK_HASH, SUBMISSION_QUEUE
from assemblyline.common.dispatcher import (
    DISPATCH_COMMAND_QUEUE,
    DISPATCH_DIRECTORY,
    DISPATCH_RESULT_QUEUE,
    DISPATCH_START_EVENTS,
    DISPATCH_TASK_ASSIGNMENT,
)
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline.remote.datatypes.queues.priority import PriorityQueue
from conftest import get_api_data

LIVE_DISPATCHER = "test-health-dispatcher-live"
STALE_DISPATCHER = "test-health-dispatcher-stale"

PRIORITY_RANGES = forge.get_constants().PRIORITY_RANGES


@pytest.fixture(scope="module", autouse=True)
def users(datastore_connection):
    create_users(datastore_connection)
    yield
    wipe_users(datastore_connection)


@pytest.fixture(scope="module")
def redis_persistent(config):
    return get_client(config.core.redis.persistent.host, config.core.redis.persistent.port, False)


@pytest.fixture(scope="module")
def redis_volatile(config):
    return get_client(config.core.redis.nonpersistent.host, config.core.redis.nonpersistent.port, False)


@pytest.fixture
def system_state(redis_persistent, redis_volatile):
    persistent_keys = [
        "system", DISPATCH_DIRECTORY, DISPATCH_TASK_HASH,
        DISPATCH_TASK_ASSIGNMENT + LIVE_DISPATCHER, DISPATCH_TASK_ASSIGNMENT + STALE_DISPATCHER,
        "m-scanning-table", "m-unique", "m-ingest", "m-alert", "m-alert-retry", "m-archive",
    ]
    volatile_keys = [SUBMISSION_QUEUE, "m-complete"] + [
        prefix + instance
        for prefix in (DISPATCH_START_EVENTS, DISPATCH_RESULT_QUEUE, DISPATCH_COMMAND_QUEUE)
        for instance in (LIVE_DISPATCHER, STALE_DISPATCHER)
    ]
    saved_system = redis_persistent.hgetall("system")

    def clear():
        redis_persistent.delete(*persistent_keys)
        redis_volatile.delete(*volatile_keys)

    clear()
    system = Hash("system", host=redis_persistent)
    system.set("dispatcher.active", True)
    system.set("ingester.active", True)
    yield system

    clear()
    if saved_system:
        redis_persistent.hset("system", mapping=saved_system)


def add_dispatcher(redis_persistent, redis_volatile, instance, last_seen, assigned=0, start=0, result=0, command=0):
    Hash(DISPATCH_DIRECTORY, host=redis_persistent).set(instance, int(last_seen))
    assignment = Hash(DISPATCH_TASK_ASSIGNMENT + instance, host=redis_persistent)
    for i in range(assigned):
        assignment.set(f"sid-{i}", {})
    for prefix, count in ((DISPATCH_START_EVENTS, start), (DISPATCH_RESULT_QUEUE, result),
                          (DISPATCH_COMMAND_QUEUE, command)):
        queue = NamedQueue(prefix + instance, host=redis_volatile)
        for i in range(count):
            queue.push({"n": i})


def fill_named(name, host, count):
    queue = NamedQueue(name, host=host)
    for i in range(count):
        queue.push({"n": i})


def get_health(session, host):
    return get_api_data(session, f"{host}/api/v4/system/health/")


def test_health_reports_dispatcher(system_state, redis_persistent, redis_volatile, login_session):
    _, session, host = login_session
    add_dispatcher(redis_persistent, redis_volatile, LIVE_DISPATCHER, time.time(),
                   assigned=3, start=2, result=1, command=0)
    active = Hash(DISPATCH_TASK_HASH, host=redis_persistent)
    for i in range(5):
        active.set(f"sid-{i}", {})
    fill_named(SUBMISSION_QUEUE, redis_volatile, 4)

    dispatcher = get_health(session, host)["components"]["dispatcher"]

    assert dispatcher["active"] is True
    assert dispatcher["instances"] == 1
    assert dispatcher["inflight"]["outstanding"] == 5
    assert dispatcher["inflight"]["per_instance"] == [3]
    assert isinstance(dispatcher["inflight"]["max"], int)
    assert dispatcher["queues"] == {"ingest": 4, "start": [2], "result": [1], "command": [0]}
    assert 0 <= dispatcher["last_seen"][LIVE_DISPATCHER] < 60


def test_health_reports_ingester(system_state, redis_persistent, redis_volatile, login_session):
    _, session, host = login_session
    scanning = Hash("m-scanning-table", host=redis_persistent)
    scanning.set("scan-1", {})
    scanning.set("scan-2", {})
    unique = PriorityQueue("m-unique", host=redis_persistent)
    unique.push(PRIORITY_RANGES["critical"][0], {"n": 1})
    unique.push(PRIORITY_RANGES["low"][1], {"n": 2})
    unique.push(PRIORITY_RANGES["low"][1], {"n": 3})
    fill_named("m-ingest", redis_persistent, 3)
    fill_named("m-complete", redis_volatile, 1)

    ingester = get_health(session, host)["components"]["ingester"]

    assert ingester["active"] is True
    assert ingester["processing"] == {"inflight": 2}
    assert ingester["queues"] == {
        "critical": 1, "high": 0, "medium": 0, "low": 2, "ingest": 3, "complete": 1,
    }


def test_health_reports_alerter(system_state, redis_persistent, login_session):
    _, session, host = login_session
    fill_named("m-alert", redis_persistent, 2)
    fill_named("m-alert-retry", redis_persistent, 1)

    alerter = get_health(session, host)["components"]["alerter"]

    assert alerter["queues"] == {"alert": 2, "alert_retry": 1}


def test_health_reports_archiver(system_state, redis_persistent, login_session):
    _, session, host = login_session
    fill_named("m-archive", redis_persistent, 3)

    archiver = get_health(session, host)["components"]["archiver"]

    assert archiver == {"queued": 3}


def test_health_status_ok(system_state, redis_persistent, redis_volatile, login_session):
    _, session, host = login_session
    add_dispatcher(redis_persistent, redis_volatile, LIVE_DISPATCHER, time.time())

    resp = get_health(session, host)

    assert resp["status"] == "ok"
    assert resp["paused"] == []
    assert resp["stale_dispatchers"] == []


def test_health_status_paused(system_state, redis_persistent, redis_volatile, login_session):
    _, session, host = login_session
    add_dispatcher(redis_persistent, redis_volatile, LIVE_DISPATCHER, time.time())
    system_state.set("ingester.active", False)

    resp = get_health(session, host)

    assert resp["status"] == "paused"
    assert resp["paused"] == ["ingester"]
    assert resp["components"]["ingester"]["active"] is False


def test_health_status_degraded_without_live_dispatcher(system_state, login_session):
    _, session, host = login_session

    resp = get_health(session, host)

    assert resp["status"] == "degraded"
    assert resp["components"]["dispatcher"]["instances"] == 0


def test_health_status_degraded_with_stale_dispatcher(system_state, redis_persistent, redis_volatile,
                                                      login_session):
    _, session, host = login_session
    add_dispatcher(redis_persistent, redis_volatile, LIVE_DISPATCHER, time.time())
    add_dispatcher(redis_persistent, redis_volatile, STALE_DISPATCHER, time.time() - 600)

    resp = get_health(session, host)

    assert resp["status"] == "degraded"
    assert resp["stale_dispatchers"] == [STALE_DISPATCHER]
    assert resp["components"]["dispatcher"]["instances"] == 2


def test_health_readable_without_admin_role(system_state, redis_persistent, redis_volatile, login_user_session):
    _, session, host = login_user_session
    add_dispatcher(redis_persistent, redis_volatile, LIVE_DISPATCHER, time.time())

    assert get_health(session, host)["status"] == "ok"
