/* global angular */
'use strict';

/**
 * Main App Module
 */
function ServiceBaseCtrl($scope, $http, $timeout) {
    //Parameters vars
    $scope.signature_list = null;
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.current_signature = null;
    $scope.current_signature_name = "";
    $scope.started = false;
    $scope.editmode = true;
    $scope.state_changed = false;
    $scope.signature_changed = false;
    $scope.current_signature_state = "TESTING";
    $scope.filtered = false;
    $scope.filter = "*";

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    //pager dependencies
    $scope.total = null;
    $scope.offset = 0;
    $scope.count = 25;
    $scope.searchText = "";
    $scope.$watch('searchText', function () {
        if ($scope.started && $scope.searchText !== undefined && $scope.searchText != null) {
            if ($scope.searchText == "" || $scope.searchText == null || $scope.searchText === undefined) {
                $scope.filter = "*";
            }
            else {
                $scope.filter = $scope.searchText;
            }

            $scope.started = false;
            if ($scope.first !== undefined) $scope.first();
            $scope.offset = 0;
            $scope.load_data();
        }
    });

    $scope.receiveClassification = function (classification) {
        $scope.current_signature.classification = classification;
    };

    $scope.add_signature = function () {
        $scope.editmode = false;
        $scope.current_signature = {
            callback: "",
            classification: "",
            comment: "",
            implant_family: "",
            score: "HIGH",
            status: "TESTING",
            threat_actor: "",
            values: []
        };
        $scope.current_signature_name = "";
        $scope.error = '';
        $scope.success = '';
        $("#myModal").modal('show');
    };

    var myModal = $("#myModal");
    myModal.on('shown.bs.modal', function () {
        $scope.$apply(function () {
            $scope.state_changed = false;
            $scope.signature_changed = false;
        });
    });

    myModal.on('show.bs.modal', function () {
        $scope.sig_temp_key = null;
        $scope.sig_temp_val = null;
        $scope.current_signature_state = $scope.current_signature.status;

        if ($scope.editmode) {
            $("#preview").addClass('active');
            $("#preview_tab").addClass('active');
            $("#edit").removeClass('active');
            $("#edit_tab").removeClass('active');
            $("#state").removeClass('active');
            $("#state_tab").removeClass('active');
        }
        else {
            $("#preview").removeClass('active');
            $("#preview_tab").removeClass('active');
            $("#edit").addClass('active');
            $("#edit_tab").addClass('active');
            $("#state").removeClass('active');
            $("#state_tab").removeClass('active');
        }
    });

    $scope.del = function () {
        swal({
                title: "Delete signature?",
                text: "You are about to delete the current signature. Are you sure?",
                type: "warning",
                showCancelButton: true,
                confirmButtonColor: "#d9534f",
                confirmButtonText: "Yes, delete it!",
                closeOnConfirm: true
            },
            function () {
                $scope.do_del();
            })
    };

    $scope.do_del = function () {
        $scope.loading_extra = true;
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'DELETE',
            url: "/api/v3/tc_signature/" + $scope.current_signature_name + "/"
        })
            .success(function () {
                $scope.loading_extra = false;
                $("#myModal").modal('hide');
                $scope.success = "Tagcheck signature '" + $scope.current_signature_name + "' successfully deleted!";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
                if (data == "") {
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
                scroll(0, 0);
            });
    };

    $scope.editSignature = function (name) {
        $scope.loading_extra = true;
        $scope.editmode = true;
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'GET',
            url: "/api/v3/tc_signature/" + name + "/"
        })
            .success(function (data) {
                $scope.loading_extra = false;
                $scope.current_signature_name = name;
                $scope.current_signature = data.api_response;
                $("#myModal").modal('show');
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
                if (data == "") {
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
            });

    };

    //Save params
    $scope.save = function (name) {
        $scope.error = '';
        $scope.success = '';

        if (!$scope.editmode) {
            $http({
                method: 'PUT',
                url: "/api/v3/tc_signature/" + name + "/",
                data: $scope.current_signature
            })
                .success(function (data) {
                    $("#myModal").modal('hide');
                    $scope.success = "Signature '" + name + "' successfully added!";
                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);

                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        }
        else {
            $http({
                method: 'POST',
                url: "/api/v3/tc_signature/" + name + "/",
                data: $scope.current_signature
            })
                .success(function (data) {
                    $("#myModal").modal('hide');
                    $scope.success = "Signature '" + name + "' succesfully updated.";

                    $timeout(function () {
                        $scope.success = "";
                        $scope.load_data();
                    }, 2000);
                })
                .error(function (data, status, headers, config) {
                    if (data == "") {
                        return;
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        }

    };

    $scope.change_state = function (name, new_status) {
        $http({
            method: 'GET',
            url: "/api/v3/tc_signature/change_status/" + name + "/" + new_status + "/"
        })
            .success(function () {
                $("#myModal").modal('hide');
                $scope.success = "Status of signature '" + name + "' successfully changed to " + new_status + ".";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);

            })
            .error(function (data, status, headers, config) {
                if (data == "") {
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
            });
    };

    $scope.set_state_change = function () {
        $scope.state_changed = true;
    };

    //Load params from datastore
    $scope.start = function () {
        $scope.load_data();
    };

    //Page traversing
    $scope.load_data = function () {
        $scope.loading_extra = true;

        $http({
            method: 'GET',
            url: "/api/v3/tc_signature/list/?offset=" + $scope.offset + "&length=" + $scope.count + "&filter=" + encodeURIComponent($scope.filter)
        })
            .success(function (data) {
                $scope.loading_extra = false;

                $scope.signature_list = data.api_response.items;
                $scope.total = data.api_response.total;

                $scope.pages = $scope.pagerArray();
                $scope.started = true;

                $scope.filtered = $scope.filter != "*";
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;

                if (data == "" || status == 400) {
                    $scope.signature_list = [];
                    $scope.total = 0;
                    $scope.filtered = true;
                    $scope.pages = $scope.pagerArray();
                    $scope.started = true;
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
                $scope.started = true;

            });
    };
}

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', ServiceBaseCtrl);

