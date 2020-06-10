/* global angular */
'use strict';

/**
 * Main App Module
 */

let app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap', 'ngSanitize', 'ui.select'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.alert_key = null;
        $scope.alert = null;
        $scope.alert_idx = 0;
        $scope.label_suggestions = ['PHISHING', 'COMPROMISE', 'CRIME', 'ATTRIBUTED', 'WHITELISTED',
            'FALSE_POSITIVE', 'REPORTED', 'MITIGATED', 'PENDING'];

        $scope.has_meta = function (alert) {
            if (alert != null && alert.hasOwnProperty('metadata')){
                let size = Object.keys(alert).length;
                return size > 0;
            }

            return false;
        };

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
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

        //Error handling
        $scope.error = '';

        $scope.has_items = function (variable) {
            return variable !== undefined && variable.length >= 1;
        };

        $scope.list_related_alerts = function (alert) {
            if (alert && (alert.group_count === undefined || alert.group_count == null)) {
                $scope.last_params = {q: "alert_id:" + alert.alert_id};
                $scope.related_ids = [alert.alert_id];
                $("#related_ids_mdl").modal('show');
            }
            else {
                let params = {
                    q: $scope.filter,
                    tc: $scope.time_slice,
                    start: $scope.start_time,
                    fq: $scope.filter_queries.slice()
                };

                if (alert) {
                    params.fq.push($scope.group_by + ":" + alert[$scope.group_by]);
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

                        return $timeout(function () {
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

        $scope.take_ownership = function (alert, alert_idx) {
            swal({
                    title: "Take ownership",
                    text: "\n\nDo you want to take ownership of this alert?\n\n",
                    type: "info",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, do it!",
                    closeOnConfirm: true
                },
                function () {
                    let ctrl = $("#" + alert_idx + "_ownership");
                    let disabled = ctrl.attr('disabled');
                    if (disabled === undefined && disabled === false) {
                        return;
                    }

                    ctrl.attr("disabled", "disabled");
                    ctrl.text("Taking Ownership...");

                    $http({
                        method: 'GET',
                        url: "/api/v4/alert/ownership/" + alert.alert_id + "/"
                    })
                        .success(function () {
                            ctrl.text("Has ownership");
                            $scope.alert['owner'] = $scope.user.uname;
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
                });

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

            let url = "/api/v4/search/alert/?query=file.md5:" + alert['file']['md5'] + "&rows=0";
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

        $scope.workflow_action = function (action) {
            if (action.priority) {
                $http({
                    method: 'POST',
                    url: "/api/v4/alert/priority/" + $scope.alert.alert_id + "/",
                    data: JSON.stringify(action.priority)
                })
                    .success(function () {
                        $scope.alert['priority'] = action.priority;
                        $scope.user_input = null;
                        $scope.last_error = "";
                    })
                    .error(function (data, status) {
                        if (status === 401){
                            window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                            return;
                        }

                        if (data.api_error_message.indexOf("already has") === -1) {
                            $scope.last_error = data.api_error_message;
                        }
                    });
            }
            if (action.status) {
                $http({
                    method: 'POST',
                    url: "/api/v4/alert/status/" + $scope.alert.alert_id + "/",
                    data: JSON.stringify(action.status)
                })
                    .success(function () {
                        $scope.alert['status'] = action.status;
                        $scope.user_input = null;
                        $scope.last_error = "";
                    })
                    .error(function (data, status) {
                        if (status === 401){
                            window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                            return;
                        }

                        if (data.api_error_message.indexOf("already has") === -1) {
                            $scope.last_error = data.api_error_message;
                        }
                    });
            }
            if (action.label.length > 0) {
                $http({
                    method: 'POST',
                    url: "/api/v4/alert/label/" + $scope.alert.alert_id + "/",
                    data: action.label
                })
                    .success(function () {
                        if ($scope.alert['label'] === undefined) {
                            $scope.alert['label'] = []
                        }
                        for (let i in action.label) {
                            let label = action.label[i];
                            if ($scope.alert['label'].indexOf(label) === -1) {
                                $scope.alert['label'].push(label);
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

                        if (data.api_error_message.indexOf("already has") === -1) {
                            $scope.last_error = data.api_error_message;
                        }
                    });
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


        $scope.prompt_workflow_action = function () {
            $scope.user_input = {
                label: [],
                priority: '',
                status: ''
            };
            $scope.last_error = "";
            $("#worflow_action").modal('show');
        };

        //Load params from datastore
        $scope.start = function () {
            $scope.loading_extra = true;
            $http({
                method: 'GET',
                url: "/api/v4/alert/" + $scope.alert_key + "/"
            })
                .success(function (data) {
                    $scope.alert = data.api_response;
                    $scope.loading_extra = false;
                })
                .error(function (data, status, headers, config) {
                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "") {
                        return;
                    }

                    $scope.loading_extra = false;
                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }

                });
        };

    });

