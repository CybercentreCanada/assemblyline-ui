/* global angular */
'use strict';

/**
 * Main App Module
 */

let app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.sha256 = null;
        $scope.binary = null;
        $scope.on_server = true;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';

        //Load params from datastore
        $scope.start = function () {
            $http({
                method: 'GET',
                url: "/api/v4/file/hex/" + $scope.sha256 + "/"
            })
                .success(function (data) {
                    $scope.hex = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "" || data === null) {
                        return;
                    }
                    else if (status === 404) {
                        $scope.on_server = false;
                        return
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }

                });
            $http({
                method: 'GET',
                url: "/api/v4/file/strings/" + $scope.sha256 + "/"
            })
                .success(function (data) {
                    $scope.string = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "" || data === null) {
                        return;
                    }
                    else if (status === 404) {
                        $scope.on_server = false;
                        return
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }

                });
            $http({
                method: 'GET',
                url: "/api/v4/file/ascii/" + $scope.sha256 + "/"
            })
                .success(function (data) {
                    $scope.ascii = data.api_response;
                })
                .error(function (data, status, headers, config) {
                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "" || data === null) {
                        return;
                    }
                    else if (status === 404) {
                        $scope.on_server = false;
                        return
                    }

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }

                });
        };

    });

