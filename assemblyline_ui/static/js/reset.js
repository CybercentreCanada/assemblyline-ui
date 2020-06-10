/* global angular */
'use strict';

/**
 * Main App Module
 */

function ResetBaseCtrl($scope, $http, $timeout) {
    $scope.password = "";
    $scope.password_confirm = "";
    $scope.reset_id = "";
    $scope.email = "";
    $scope.error = "";
    $scope.reseted = false;
    $scope.link_sent = false;

    //Reset password API
    $scope.reset = function () {
        $scope.error = '';
        $scope.loading = true;

        $http({
            method: 'POST',
            url: "/api/v4/auth/reset_pwd/",
            data: {
                reset_id: $scope.reset_id,
                password: $scope.password,
                password_confirm: $scope.password_confirm}
            })
            .success(function () {
                $scope.reseted = true;
                $timeout(function(){
                    window.location = "/login.html";
                }, 2000);
            })
            .error(function (data) {
                $scope.error = data.api_error_message;
                $scope.loading = false;
            });
    };

    //Get reset link API
    $scope.get_reset_link = function () {
        $scope.error = '';
        $scope.loading = true;

        $http({
            method: 'POST',
            url: "/api/v4/auth/get_reset_link/",
            data: {email: $scope.email}
        })
        .success(function () {
            $scope.loading = false;
            $scope.link_sent = true;
        })
        .error(function (data) {
            $scope.error = data.api_error_message;
            $scope.loading = false;
        });
    };

    //Load current_user from datastore
    $scope.start = function () {};
}

let app = angular.module('app', []);
app.controller('ALController', ResetBaseCtrl);
