/* global angular */
'use strict';

/**
 * Main App Module
 */

function SettingsBaseCtrl($scope, $http, $timeout, $window) {
    //Parameters vars
    $scope.tos = false;
    $scope.user = null;
    $scope.loading = false;

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    //Save params
    $scope.send_tos_agreement = function () {
        $scope.error = '';
        $scope.success = '';
        $http({
            method: 'GET',
            url: "/api/v4/user/tos/" + $scope.user.uname + "/"
        })
            .success(function () {
                $scope.success = "The date and time at which you've agreed to the current Terms of Service was save in your user settings.";
                $scope.error = "";
                $timeout(function () {
                    $window.location = "/"
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "" || data === null) {
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

    //Load params from datastore
    $scope.start = function () {
    };
}

let app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', SettingsBaseCtrl);
