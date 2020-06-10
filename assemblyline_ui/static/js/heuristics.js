/* global angular */
'use strict';

/**
 * Main App Module
 */
let app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.heuristic_list = null;
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "id:*";

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
                if ($scope.searchText === "") {
                    $scope.filter = "id:*";
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

        $scope.viewHeuristic = function (heuristic) {
            $scope.error = '';
            $scope.success = '';
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v4/heuristics/" + heuristic + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_heuristic = data.api_response;

                    for (let i in $scope.heuristics_stats) {
                        if ($scope.heuristics_stats[i]["heur_id"] === $scope.current_heuristic["heur_id"]) {
                            $scope.current_heuristic["count"] = $scope.heuristics_stats[i]["count"];
                            $scope.current_heuristic["min"] = $scope.heuristics_stats[i]["min"];
                            $scope.current_heuristic["avg"] = $scope.heuristics_stats[i]["avg"];
                            $scope.current_heuristic["max"] = $scope.heuristics_stats[i]["max"];
                            break;
                        }
                    }

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
            $scope.load_data();
            $scope.load_stats();
        };

        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v4/search/heuristic/?offset=" + $scope.offset + "&rows=" + $scope.rows + "&query=" + encodeURIComponent($scope.filter)
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    $scope.heuristics_list = data.api_response.items;
                    $scope.total = data.api_response.total;
                    $scope.pages = $scope.pagerArray();
                    $scope.started = true;

                    $scope.filtered = $scope.filter !== "id:*";
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "" || data === null) return;

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    $scope.started = true;

                });
        };

        $scope.load_stats = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v4/heuristics/stats/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.heuristics_stats = data.api_response.items;
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "" || data === null) return;

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

