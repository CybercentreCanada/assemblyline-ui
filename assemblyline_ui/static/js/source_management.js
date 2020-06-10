/* global angular */
'use strict';

/**
 * Main App Module
 */
function ServiceBaseCtrl($scope, $http, $timeout) {
    //Parameters lets
    $scope.source_map = null;
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.current_source = null;
    $scope.current_source_name = null;
    $scope.current_service = null;
    $scope.editmode = false;
    $scope.started = false;

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    $scope.obj_len = function (o) {
        if (o === undefined || o == null) return 0;
        return Object.keys(o).length;
    };

    $scope.receiveClassification = function (classification) {
        $scope.current_source.default_classification = classification;
    };

    $scope.del = function () {
        swal({
                title: "Delete signature source?",
                text: "You are about to delete the current signature source. Are you sure?",
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
            url: "/api/v4/signature/sources/" + $scope.current_service + "/" + $scope.current_source.name + "/"
        })
            .success(function () {
                $scope.loading_extra = false;
                $("#myModal").modal('hide');
                $scope.success = "Signature source '" + $scope.current_source.name + "' successfully deleted!";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "") {
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

    $scope.reset_source = function(){
        $("#source_uri").removeClass('has-error');
        $("#source_resulting_filename").removeClass('has-error');
        $scope.error = '';
        $scope.success = '';
        $scope.comp_temp_error = null;
        $scope.conf_temp = {
            key: "",
            val: ""
        };
    };

    $scope.save = function () {
        $scope.reset_source();
        if ($scope.current_source.uri === "" || $scope.current_source.uri === null || $scope.current_source.uri === undefined){
            $("#source_uri").addClass('has-error');
            return;
        }

        if ($scope.current_source.name === "" || $scope.current_source.name === null || $scope.current_source.name === undefined){
            $("#source_resulting_filename").addClass('has-error');
            return;
        }

        $scope.loading_extra = true;
        if ($scope.editmode){
            $http({
                method: 'POST',
                url: "/api/v4/signature/sources/" + $scope.current_service + "/" + $scope.current_source_name + "/",
                data: $scope.current_source
            })
            .success(function () {
                $scope.loading_extra = false;
                $("#myModal").modal('hide');
                $scope.success = "Signature source '" + $scope.current_source.name + "' successfully updated!";

                $scope.current_source = null;
                $scope.current_source_name = null;
                $scope.current_service = null;

                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "") {
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
        }
        else{
            $http({
                method: 'PUT',
                url: "/api/v4/signature/sources/" + $scope.current_service + "/",
                data: $scope.current_source
            })
            .success(function () {
                $scope.loading_extra = false;
                $("#myModal").modal('hide');
                $scope.success = "Signature source '" + $scope.current_source.name + "' successfully added!";

                $scope.current_source = null;
                $scope.current_source_name = null;
                $scope.current_service = null;

                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "") {
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
        }

    };

    $scope.addSource = function (service) {
        $scope.editmode = false;
        $scope.reset_source();

        $scope.current_service = service;
        $scope.current_source = {};
        $("#myModal").modal('show');
    };

    $scope.edit_source_config = function (source, service) {
        $scope.editmode = true;
        $scope.reset_source();

        $scope.current_service = service;
        $scope.current_source_name = source.name;
        $scope.current_source = source;
        $("#myModal").modal('show');
    };

    $scope.comp_temp_error = null;
    $scope.conf_temp = {
        key: "",
        val: ""
    };

    $scope.remove_header = function (key, val) {
        for (let i in $scope.current_source.headers){
            if ($scope.current_source.headers[i].name === key && $scope.current_source.headers[i].value === val){
                $scope.current_source.headers.splice(i, 1);
                return;
            }
        }
    };

    $scope.add_header = function () {
        $("#new_conf_temp_key").removeClass("has-error");
        $("#new_conf_temp_val").removeClass("has-error");
        $scope.conf_temp_error = null;

        if (!("headers" in $scope.current_source)){
            $scope.current_source.headers = [];
        }

        if ($scope.conf_temp.key === "" || $scope.conf_temp.key == null) {
            $scope.conf_temp_error = "Header name is required.";
            $("#new_conf_temp_key").addClass("has-error");
            $("#new_conf_temp_val").removeClass("has-error");
            return;
        }

        if ($scope.conf_temp.val === "" || $scope.conf_temp.val == null) {
            $scope.conf_temp_error = "Each header requires a value.";
            $("#new_conf_temp_key").removeClass("has-error");
            $("#new_conf_temp_val").addClass("has-error");
            return;
        }
        $scope.current_source.headers.push({
            name: $scope.conf_temp.key,
            value: $scope.conf_temp.val
        });

        $scope.conf_temp = {
            key: "",
            val: ""
        };
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
            url: "/api/v4/signature/sources/"
        })
            .success(function (data) {
                $scope.loading_extra = false;

                $scope.source_map = data.api_response;
                $scope.started = true;
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;

                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "" || status === 400) {
                    $scope.source_map = {};
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

let app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', ServiceBaseCtrl);

