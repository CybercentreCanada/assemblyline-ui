/* global angular */
'use strict';

/**
 * Main App Module
 */
let app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout, $window) {
        //Parameters vars
        $scope.user = null;
        $scope.options = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.started = false;
        $scope.data = null;
        $scope.sid = null;
        $scope.file_tree = null;
        $scope.important_files = null;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        $scope.obj_len = function (o) {
            if (o === undefined || o == null) return 0;
            return Object.keys(o).length;
        };

        $scope.empty = function (obj) {
            if (obj === null || obj === undefined) {
                return true;
            }
            return Object.keys(obj).length === 0;
        };

        $scope.do_print = function(){
            $window.print();
        };

        //Error handling
        $scope.error = '';

        $scope.get_report = function(){
            $http({
                method: 'GET',
                url: "/api/v4/submission/report/" + $scope.sid + "/"
            })
            .success(function (data) {
                $scope.started = true;
                $scope.data = data.api_response;
                $scope.file_tree = $scope.data.file_tree;
                $scope.important_files = $scope.data.important_files;
            })
            .error(function (data, status, headers, config) {
                $scope.started = true;
                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "") {
                    return;
                }

                if (status === 404){
                    $timeout(function () {
                    swal({
                            title: "Submission ID does not exists",
                            text: "\nThe selected submission ID cannot be found it the system. You'll be returned to the list of your submissions...",
                            type: "error",
                            confirmButtonColor: "#d9534f",
                            confirmButtonText: "Close",
                            closeOnConfirm: false
                        },
                        function () {
                            $window.location = "/submissions.html";
                        });
                }, 100);
                }
                else {
                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                }
            });
        };


        //Load params from datastore
        $scope.start = function () {
            if ($scope.sid == null || $scope.sid === "") {
                $scope.started = true;
                $timeout(function () {
                    swal({
                            title: "Submission ID does not exists",
                            text: "\nThe selected submission ID cannot be found it the system. You'll be returned to the list of your submissions...",
                            type: "error",
                            confirmButtonColor: "#d9534f",
                            confirmButtonText: "Close",
                            closeOnConfirm: false
                        },
                        function () {
                            $window.location = "/submissions.html";
                        });
                }, 100);
            } else {
                $scope.get_report();
            }
        };
    });

