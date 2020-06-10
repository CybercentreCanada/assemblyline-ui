/* global angular */
'use strict';

/**
 * Main App Module
 */
let app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters lets
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.stats_list = null;
        $scope.stats_filtered = null;
        $scope.stats_output = null;
        $scope.sort = {"column": "sid", "order": true};
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "*";
        $scope.timestamp = null;
        $scope.order = false;
        $scope.total = 0;
        $scope.offset = 0;
        $scope.rows = 25;
        $scope.searchText = "";

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';

        $scope.$watch('searchText', function () {
            if ($scope.started && $scope.searchText !== undefined && $scope.searchText != null) {
                $scope.searchText = $scope.searchText.toLowerCase();
                if ($scope.searchText === "") {
                    $scope.filter = "*";
                }
                else {
                    $scope.filter = $scope.searchText;
                }

                let filtered = [];
                for (let sig in $scope.stats_list) {
                    if (JSON.stringify($scope.stats_list[sig]).toLowerCase().indexOf($scope.searchText) > -1) {
                        filtered.push($scope.stats_list[sig]);
                    }
                }
                if (filtered !== []) {
                    $scope.stats_filtered = filtered;
                }
                //$scope.started = false;
                if ($scope.first !== undefined) $scope.first();
                $scope.offset = 0;
                $scope.sort_stats();
                $scope.load_data();
            }
        });

        $scope.viewSignature = function (signature_id) {
            $scope.editmode = true;

            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v4/signature/" + signature_id + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_signature = data.api_response;
                    $("#myModal").modal('show');
                })
                .error(function (data, status, headers, config) {
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
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                });
        };

        $scope.start = function () {
            $scope.get_stats_data();
        };

        $scope.sort_stats = function (column) {
            if (column !== undefined) {
                if ($scope.sort["column"] === column) {
                    $scope.sort["order"] = !$scope.sort["order"];
                }
                else {
                    $scope.sort["column"] = column;
                    $scope.sort["order"] = true;
                }
            }

            if ($scope.filter === "*") {
                $scope.stats_list.sort($scope.sort_by($scope.sort["column"], $scope.sort["order"]));
            }
            else {
                $scope.stats_filtered.sort($scope.sort_by($scope.sort["column"], $scope.sort["order"]));
            }

            $scope.load_data();
        };

        $scope.sort_by = function (field, order) {

            let field1 = field;
            let field2 = "sid";

            if (order) {
                order = 1;
            }
            else {
                order = -1;
            }

            return function (a, b) {
                if (a[field1] !== b[field1]) {
                    if (a[field1] > b[field1]) return 1 * order;
                    if (a[field1] < b[field1]) return -1 * order;
                    return 0;
                }
                if (a[field2] > b[field2]) return -1 * order;
                if (a[field2] < b[field2]) return 1 * order;
                return 0;
            }

        };


        $scope.load_data = function () {
            if ($scope.filter === "*") {
                $scope.total = $scope.stats_list.length;
                $scope.stats_output = $scope.stats_list.slice($scope.offset, $scope.offset + $scope.rows);
                $scope.pages = $scope.pagerArray();
                $scope.filtered = false;
            }
            else {
                $scope.total = $scope.stats_filtered.length;
                $scope.stats_output = $scope.stats_filtered.slice($scope.offset, $scope.offset + $scope.rows);
                $scope.pages = $scope.pagerArray();
                $scope.filtered = true;
            }
        };

        $scope.get_stats_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v4/signature/stats/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.stats_list = data.api_response;
                    $scope.total = data.api_response.length;
                    $scope.started = true;
                    $scope.sort_stats();
                    $scope.load_data();
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
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };
    });

