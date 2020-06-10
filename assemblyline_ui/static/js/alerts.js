/* global angular */
'use strict';

/**
 * Main App Module
 */
let app = angular.module('app', ['utils', 'search', 'infinite-scroll', 'ui.bootstrap', 'ngSanitize', 'ui.select'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.alert_list = null;
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "";
        $scope.tc_array = null;
        $scope.tc = null;
        $scope.time_separator = "";
        $scope.tc_start = null;
        $scope.label_suggestions = ['PHISHING', 'COMPROMISE', 'CRIME', 'ATTRIBUTED', 'WHITELISTED',
            'FALSE_POSITIVE', 'REPORTED', 'MITIGATED', 'PENDING'];

        $scope.total = 0;
        $scope.offset = 0;
        $scope.rows = 25;
        $scope.filtering_group_by = [];
        $scope.non_filtering_group_by = [];
        $scope.group_by = 'file.sha256';
        $scope.counted_total = 0;
        $scope.view_type = "grouped";
        $scope.filter_queries = [];
        $scope.forced_filter = "";
        $scope.field_fq = null;
        $scope.current_alert_idx = null;
        $scope.current_alert = null;
        $scope.modal_error = null;
        $scope.user_input = null;
        $scope.related_ids = null;
        $scope.last_params = null;

        $scope.getKeys = function (o) {
            try {
                return Object.keys(o);
            } catch (ex) {
                return [];
            }
        };

        $scope.getToday = function () {
            let today = new Date();
            let dd = today.getDate();
            if (dd < 10) {
                dd = '0' + dd;
            } else {
                dd = '' + dd;
            }
            let mm = today.getMonth() + 1;
            if (mm < 10) {
                mm = '0' + mm;
            } else {
                mm = '' + mm;
            }
            return today.getFullYear() + mm + dd;
        };

        $scope.get_default_view = function(){
            if ($scope.settings.submission_view === "report"){
                return 'report';
            }
            else{
                return 'submission_detail';
            }
        };

        $scope.send_malicious_verdict = function (alert){
            $scope.send_verdict(alert, 'malicious');
        };

        $scope.send_non_malicious_verdict = function (alert){
            $scope.send_verdict(alert, 'non_malicious');
        };

        $scope.send_verdict = function (alert, verdict) {
            if (alert.verdict[verdict].indexOf($scope.user.uname) !== -1 || $scope.loading_extra){
                return
            }

            $scope.loading_extra = true;
            $http({
                method: 'PUT',
                url: "/api/v4/alert/verdict/" + alert.alert_id + "/" + verdict + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    if (!data.api_response.success){
                        return
                    }
                    if (verdict === "malicious"){
                        if (alert.verdict.malicious.indexOf($scope.user.uname) === -1){
                            alert.verdict.malicious.push($scope.user.uname)
                        }
                        if (alert.verdict.non_malicious.indexOf($scope.user.uname) !== -1){
                            alert.verdict.non_malicious.splice(alert.verdict.non_malicious.indexOf($scope.user.uname), 1)
                        }
                    }
                    else{
                        if (alert.verdict.non_malicious.indexOf($scope.user.uname) === -1){
                            alert.verdict.non_malicious.push($scope.user.uname)
                        }
                        if (alert.verdict.malicious.indexOf($scope.user.uname) !== -1){
                            alert.verdict.malicious.splice(alert.verdict.malicious.indexOf($scope.user.uname), 1)
                        }
                    }
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;
                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "" || data === null) {
                        return;
                    }

                    $scope.loading_extra = false;
                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    } else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        };

        $scope.has_items = function (variable) {
            return variable !== undefined && variable.length >= 1;
        };

        $scope.workflow_action = function (action) {
            if ($scope.current_alert && ($scope.current_alert.group_count === undefined || $scope.current_alert.group_count == null)) {
                if (action.priority) {
                    $http({
                        method: 'POST',
                        url: "/api/v4/alert/priority/" + $scope.current_alert.alert_id + "/",
                        data: JSON.stringify(action.priority)
                    })
                        .success(function () {
                            $scope.alert_list[$scope.current_alert_idx]['priority'] = action.priority;
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data, status) {
                            if (status === 401){
                                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                return;
                            }

                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.status) {
                    $http({
                        method: 'POST',
                        url: "/api/v4/alert/status/" + $scope.current_alert.alert_id + "/",
                        data: JSON.stringify(action.status)
                    })
                        .success(function () {
                            $scope.alert_list[$scope.current_alert_idx]['status'] = action.status;
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data, status) {
                            if (status === 401){
                                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                return;
                            }

                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.label.length > 0) {
                    $http({
                        method: 'POST',
                        url: "/api/v4/alert/label/" + $scope.current_alert.alert_id + "/",
                        data: action.label
                    })
                        .success(function () {
                            if ($scope.alert_list[$scope.current_alert_idx]['label'] === undefined) {
                                $scope.alert_list[$scope.current_alert_idx]['label'] = []
                            }
                            for (let i in action.label) {
                                let label = action.label[i];
                                if ($scope.alert_list[$scope.current_alert_idx]['label'].indexOf(label) === -1) {
                                    $scope.alert_list[$scope.current_alert_idx]['label'].push(label);
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data, status) {
                            if (status === 401){
                                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                return;
                            }

                            $scope.last_error = data.api_error_message;
                        });
                }
            } else {
                let params = {
                    q: $scope.filter,
                    tc: $scope.tc,
                    tc_start: $scope.tc_start,
                    fq: $scope.filter_queries.slice()
                };

                if ($scope.current_alert) {
                    params.fq.push($scope.group_by + ":" + $scope.get_object_value($scope.current_alert, $scope.group_by));
                }

                if (action.priority) {
                    $http({
                        method: 'POST',
                        url: "/api/v4/alert/priority/batch/",
                        data: JSON.stringify(action.priority),
                        params: params
                    })
                        .success(function () {
                            if ($scope.current_alert_idx !== undefined) {
                                $scope.alert_list[$scope.current_alert_idx]['priority'] = action.priority;
                            } else {
                                for (let idx in $scope.alert_list) {
                                    $scope.alert_list[idx]['priority'] = action.priority;
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data, status) {
                            if (status === 401){
                                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                return;
                            }

                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.status) {
                    $http({
                        method: 'POST',
                        url: "/api/v4/alert/status/batch/",
                        data: JSON.stringify(action.status),
                        params: params
                    })
                        .success(function () {
                            if ($scope.current_alert_idx !== undefined) {
                                $scope.alert_list[$scope.current_alert_idx]['status'] = action.status;
                            } else {
                                for (let idx in $scope.alert_list) {
                                    $scope.alert_list[idx]['status'] = action.status;
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data, status) {
                            if (status === 401){
                                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                return;
                            }

                            $scope.last_error = data.api_error_message;
                        });
                }
                if (action.label.length > 0) {
                    $http({
                        method: 'POST',
                        url: "/api/v4/alert/label/batch/",
                        data: action.label,
                        params: params
                    })
                        .success(function () {
                            if ($scope.current_alert_idx !== undefined) {
                                if ($scope.alert_list[$scope.current_alert_idx]['label'] === undefined) {
                                    $scope.alert_list[$scope.current_alert_idx]['label'] = []
                                }
                                for (let i in action.label) {
                                    let label = action.label[i];
                                    if ($scope.alert_list[$scope.current_alert_idx]['label'].indexOf(label) === -1) {
                                        $scope.alert_list[$scope.current_alert_idx]['label'].push(label);
                                    }
                                }
                            } else {
                                for (let idx in $scope.alert_list) {
                                    if ($scope.alert_list[idx]['label'] === undefined) {
                                        $scope.alert_list[idx]['label'] = []
                                    }
                                    for (let x in action.label) {
                                        let label_item = action.label[x];
                                        if ($scope.alert_list[idx]['label'].indexOf(label_item) === -1) {
                                            $scope.alert_list[idx]['label'].push(label_item);
                                        }
                                    }
                                }
                            }
                            $scope.user_input = null;
                            $scope.last_error = "";
                        })
                        .error(function (data, status) {
                            if (status === 401){
                                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                return;
                            }

                            $scope.last_error = data.api_error_message;
                        });
                }
            }

            $("#worflow_action").modal('hide');
        };

        $scope.$watch('last_error', function () {
            if ($scope.last_error) {
                swal({
                    title: "ERROR",
                    text: $scope.last_error,
                    type: "error",
                    closeOnConfirm: true
                })
            }
        });


        $scope.prompt_workflow_action = function (alert, alert_idx) {
            $scope.current_alert_idx = alert_idx;
            $scope.current_alert = alert;
            if (alert !== undefined) {
                $scope.current_alert.group_by = $scope.get_object_value(alert, $scope.group_by);
            }
            $scope.user_input = {
                label: [],
                priority: '',
                status: ''
            };
            $scope.last_error = "";
            $("#worflow_action").modal('show');
        };

        $scope.take_ownership = function (alert, alert_idx) {
            if (alert && (alert.group_count === undefined || alert.group_count == null)) {
                swal({
                        title: "Take ownership",
                        text: "\n\nDo you want to take ownership of this alert?\n\n" + alert.alert_id,
                        type: "info",
                        showCancelButton: true,
                        confirmButtonColor: "#d9534f",
                        confirmButtonText: "Yes, do it!",
                        closeOnConfirm: true
                    },
                    function () {
                        $http({
                            method: 'GET',
                            url: "/api/v4/alert/ownership/" + alert.alert_id + "/"
                        })
                            .success(function () {
                                $scope.alert_list[alert_idx]['owner'] = $scope.user.uname;
                            })
                            .error(function (data, status) {
                                if (status === 401){
                                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                    return;
                                }

                                $timeout(function () {
                                    swal({
                                        title: "Error while taking ownership",
                                        text: data.api_error_message,
                                        type: "error",
                                        showCancelButton: false,
                                        confirmButtonColor: "#d9534f",
                                        confirmButtonText: "Dismiss",
                                        closeOnConfirm: true
                                    });
                                }, 250);
                            });
                    });
            } else {
                let params = {
                    q: $scope.filter,
                    tc: $scope.tc,
                    tc_start: $scope.tc_start,
                    fq: $scope.filter_queries.slice()
                };

                let text = "\n\nDo you want to take ownership of all " + $scope.total + " alert(s) filtered in the current view?";
                if (alert) {
                    params.fq.push($scope.group_by + ":" + $scope.get_object_value(alert, $scope.group_by));
                    text = "\n\nDo you want to take ownership of " + alert.group_count + " alert(s) related to this " + $scope.group_by + "?\n\n" + $scope.get_object_value(alert, $scope.group_by);
                }

                swal({
                        title: "Multiple Take ownership",
                        text: text,
                        type: "warning",
                        showCancelButton: true,
                        confirmButtonColor: "#d9534f",
                        confirmButtonText: "Yes, do it!",
                        closeOnConfirm: true
                    },
                    function () {
                        $http({
                            method: 'GET',
                            url: "/api/v4/alert/ownership/batch/",
                            params: params
                        })
                            .success(function () {
                                if (alert_idx) {
                                    $scope.alert_list[alert_idx]['owner'] = $scope.user.uname;
                                } else {
                                    for (let idx in $scope.alert_list) {
                                        $scope.alert_list[idx]['owner'] = $scope.user.uname;
                                    }
                                }
                            })
                            .error(function (data, status) {
                                if (status === 401){
                                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                                    return;
                                }

                                $timeout(function () {
                                    swal({
                                        title: "Error while taking ownership",
                                        text: data.api_error_message,
                                        type: "error",
                                        showCancelButton: false,
                                        confirmButtonColor: "#d9534f",
                                        confirmButtonText: "Dismiss",
                                        closeOnConfirm: true
                                    });
                                }, 250);
                            });
                    });
            }
        };

        $scope.get_object_value = function(obj, key){
            let res = key.split(".", 2);
            if (res.length === 1){
                return obj[res[0]];
            }
            else{
                return $scope.get_object_value(obj[res[0]], res[1]);
            }
        };

        $scope.list_related_alerts = function (alert) {
            if (alert && (alert.group_count === undefined || alert.group_count == null)) {
                $scope.last_params = {q: "alert_id:" + alert.alert_id};
                $scope.related_ids = [alert.alert_id];
                $("#related_ids_mdl").modal('show');
            } else {
                let params = {
                    q: $scope.filter,
                    tc: $scope.tc,
                    tc_start: $scope.tc_start,
                    fq: $scope.filter_queries.slice()
                };

                if (alert) {
                    params.fq.push($scope.group_by + ":" + $scope.get_object_value(alert, $scope.group_by));
                }

                $scope.last_params = params;

                $http({
                    method: 'GET',
                    url: "/api/v4/alert/related/",
                    params: params
                })
                    .success(function (data) {
                        $scope.related_ids = data.api_response;
                        $("#related_ids_mdl").modal('show');
                    })
                    .error(function (data, status) {
                        if (status === 401){
                            window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                            return;
                        }

                        $timeout(function () {
                            swal({
                                title: "Error while generating list of IDs.",
                                text: data.api_error_message,
                                type: "error",
                                showCancelButton: false,
                                confirmButtonColor: "#d9534f",
                                confirmButtonText: "Dismiss",
                                closeOnConfirm: true
                            });
                        }, 250);
                    });
            }
        };

        $scope.lock_in_timestamp = function (alert) {
            $scope.filter_queries.push("reporting_ts:[" + alert.reporting_ts + " TO *]");
            $scope.gen_forced_filter(false);
            let url = "/alerts.html?filter=" + encodeURIComponent($scope.filter) + "&tc=" + $scope.tc + "&view_type=" + $scope.view_type + "&group_by=" + $scope.group_by;
            for (let key in $scope.filter_queries) {
                let fq = $scope.filter_queries[key];
                url += "&fq=" + fq;
            }
            window.location = url;
        };

        $scope.count_similar = function (alert, alert_idx) {
            let ctrl = $("#" + alert_idx + "_similar");
            let disabled = ctrl.attr('disabled');
            if (disabled === undefined && disabled === false) {
                return;
            }

            ctrl.attr("disabled", "disabled");
            ctrl.removeClass("btn-danger");
            ctrl.addClass("btn-default");
            ctrl.text("Counting alerts...");

            let url = "/api/v4/search/alert/?query=" + $scope.group_by + ":\"" + $scope.get_object_value(alert, $scope.group_by) + "\"&rows=0";
            $http({method: 'GET', url: url})
                .success(function (data) {
                    ctrl.removeClass("btn-default");
                    ctrl.addClass("btn-primary");
                    ctrl.text(data.api_response.total + " similar alerts")
                })
                .error(function (data, status) {
                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    ctrl.removeClass("btn-default");
                    ctrl.addClass("btn-danger");
                    ctrl.removeAttr('disabled');
                    ctrl.text("Error: " + data.api_error_message + " (Retry?)");
                });
        };

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.invalid_query = "";

        $scope.filterData = function (searchText) {
            let url = "/alerts.html?filter=" + encodeURIComponent(searchText) + "&tc=" + this.tc + "&view_type=" + $scope.view_type + "&group_by=" + this.group_by;
            for (let key in $scope.filter_queries) {
                let fq = $scope.filter_queries[key];
                url += "&fq=" + fq;
            }

            window.location = url;
        };

        $scope.has_meta = function (alert) {
            if (alert != null && alert.hasOwnProperty('metadata')) {
                let size = Object.keys(alert).length;
                return size > 0;
            }

            return false;
        };

        //Load params from datastore
        $scope.start = function () {
            $scope.offset -= $scope.rows;
            $scope.gen_forced_filter(true);
            $scope.possible_group_by = $scope.filtering_group_by.concat($scope.non_filtering_group_by).sort();
        };

        $scope.gen_forced_filter = function (do_count) {
            $scope.forced_filter = "";
            for (let key in $scope.filter_queries) {
                let fq = $scope.filter_queries[key];
                if (fq.indexOf($scope.group_by + ":\"") !== -1) {
                    $scope.field_fq = fq;
                }
                $scope.forced_filter += "&fq=" + fq;
            }
            if ($scope.view_type === 'list' && $scope.tc_start) {
                $scope.forced_filter += "&tc_start=" + $scope.tc_start;
                if ($scope.field_fq != null && do_count) {
                    $scope.count_instances();
                }
            }
        };

        $scope.getNextAlertPage = function () {
            $scope.offset += $scope.rows;
            $scope.load_data();
        };

        $scope.clear_forced_filter = function () {
            let url = "";

            if ($scope.view_type === "list") {
                let new_fq = [];
                for (let fq_key in $scope.filter_queries) {
                    let item = $scope.filter_queries[fq_key];
                    if (item.indexOf($scope.group_by + ":") !== -1) {
                        new_fq.push(item);
                    }
                }

                url = "/alerts.html?filter=" + encodeURIComponent($scope.filter) + "&tc=&view_type=" + $scope.view_type + "&group_by=" + $scope.group_by;
                for (let key in new_fq) {
                    let fq = new_fq[key];
                    url += "&fq=" + fq;
                }
            } else {
                url = "/alerts.html?filter=" + encodeURIComponent($scope.filter) + "&tc=" + $scope.tc + "&view_type=" + $scope.view_type + "&group_by=" + $scope.group_by;
            }

            window.location = url;
        };

        $scope.count_instances = function () {
            let url = "/api/v4/search/alert/?query=" + encodeURIComponent($scope.field_fq) + "&rows=0";

            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.total_instances = data.api_response.total;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    } else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        };

        $scope.load_data = function () {
            let url = null;
            let url_params = "?offset=" + $scope.offset + "&rows=" + $scope.rows + "&q=" + encodeURIComponent($scope.filter);
            $scope.loading = true;
            if ($scope.view_type === "list") {
                url = "/api/v4/alert/list/";
            } else {
                url = "/api/v4/alert/grouped/" + $scope.group_by + "/";
            }

            if ($scope.tc_start != null) {
                url_params += "&tc_start=" + $scope.tc_start;
            }

            if ($scope.tc !== "") {
                url_params += "&tc=" + $scope.tc;
            }

            for (let key in $scope.filter_queries) {
                let fq = $scope.filter_queries[key];
                url_params += "&fq=" + fq;
            }

            url += url_params;

            $http({
                method: 'GET',
                url: url
            })
                .success(function (data) {
                    $scope.loading = false;

                    if (!$scope.started) {
                        $scope.alert_list = []
                    }
                    Array.prototype.push.apply($scope.alert_list, data.api_response.items);
                    $scope.total = data.api_response.total;
                    if ($scope.view_type !== "list") {
                        $scope.counted_total += data.api_response.counted_total;
                        $scope.tc_start = data.api_response.tc_start;
                    } else {
                        $scope.counted_total += data.api_response.items.length;
                    }
                    $scope.started = true;

                    $scope.filtered = (($scope.filter !== "*" && $scope.filter !== "") || $scope.tc !== "" || $scope.forced_filter !== "" || $scope.filtering_group_by.indexOf($scope.group_by) !== -1);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "") return;

                    if (status === 400) {
                        $timeout(function () {
                            $("#search-term").addClass("has-error");
                            let sb = $("#search-box");
                            sb.select();
                            sb.focus();
                        }, 0);

                        $scope.invalid_query = data.api_error_message;

                        $scope.alert_list = [];
                        $scope.total = 0;
                        $scope.filtered = true;
                        $scope.started = true;
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    } else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });

            $scope.stats_url = "/api/v4/alert/statistics/" + url_params + "&fq=" + $scope.group_by + ":*";
            $scope.labels_url = "/api/v4/alert/labels/" + url_params + "&fq=" + $scope.group_by + ":*";
            $scope.statuses_url = "/api/v4/alert/statuses/" + url_params + "&fq=" + $scope.group_by + ":*";
            $scope.priorities_url = "/api/v4/alert/priorities/" + url_params + "&fq=" + $scope.group_by + ":*";

            if ($scope.view_type !== "list") {
                $scope.get_labels();
                $scope.get_statuses();
                $scope.get_priorities();
            }

        };

        $scope.get_labels = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.labels_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_labels = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    } else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.get_priorities = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.priorities_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_priorities = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    } else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.get_statuses = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.statuses_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_statuses = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    } else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.show_statistics = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: $scope.stats_url
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.statistics = data.api_response;
                    $("#statsModal").modal('show');
                    $timeout(function () {
                        $scope.overflows();
                    }, 0);
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "") return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    } else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.safe_key = function(key){
            return key.replace(/\./g, "_");
        };

        $scope.expand = function (id) {
            $("#" + id).removeClass("expandable-tags");
            $("#" + id + "_expand").addClass("ng-hide");
        };

        $scope.overflows = function () {
            let skipped = 0;
            for (let stat_id in $scope.statistics) {
                stat_id = $scope.safe_key(stat_id);
                let target = $("#" + stat_id)[0];
                if (target !== undefined){
                    if (target.scrollHeight === 0) {
                        skipped += 1;
                        continue;
                    }
                    if (target.offsetHeight >= target.scrollHeight &&
                        target.offsetWidth >= target.scrollWidth) {
                        $scope.expand(stat_id);
                    }
                }
            }
            if (skipped === $scope.getKeys($scope.statistics).length) {
                $timeout(function () {
                    $scope.overflows();
                }, 0);
            }
        };

        window.onunload = function () {
        };
    });

