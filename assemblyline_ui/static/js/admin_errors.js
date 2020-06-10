/* global angular */
'use strict';

/**
 * Main App Module
 */
let app = angular.module('app', ['utils', 'search', 'infinite-scroll', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.error_list = null;
        $scope.started = false;
        $scope.filtered = false;
        $scope.filter = "";

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
        $scope.invalid_query = "";

        $scope.filterData = function (searchText) {
            window.location = "/admin/errors.html?filter=" + encodeURIComponent(searchText);
        };

        //Load params from datastore
        $scope.start = function () {
            $scope.offset -= $scope.rows;
        };

        $scope.getErrorHash = function (key) {
            let ehash = key.substr(65, key.length);

            if (ehash.indexOf(".e") !== -1) {
                ehash = ehash.substr(ehash.indexOf(".e") + 2, ehash.length);
            }

            return ehash;
        };

        $scope.getNextErrorPage = function () {
            $scope.offset += $scope.rows;
            $scope.load_data();
        };

        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v4/error/list/?offset=" + $scope.offset + "&rows=" + $scope.rows + "&query=" + encodeURIComponent($scope.filter)
            })
                .success(function (data) {
                    $scope.loading_extra = false;

                    if (!$scope.started) {
                        $scope.error_list = []
                    }
                    Array.prototype.push.apply($scope.error_list, data.api_response.items);
                    $scope.total = data.api_response.total;
                    $scope.started = true;

                    $scope.filtered = $scope.filter !== "";
                })
                .error(function (data, status, headers, config) {
                    $scope.loading_extra = false;

                    if (status === 401){
                        window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                        return;
                    }

                    if (data === "" || data === null) return;

                    if (status === 400) {
                        $timeout(function () {
                            $("#search-term").addClass("has-error");
                            let ctrl = $("#search-box");
                            ctrl.select();
                            ctrl.focus();
                        }, 0);

                        $scope.invalid_query = data.api_error_message;

                        $scope.error_list = [];
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
        };
    });

