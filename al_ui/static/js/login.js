/* global angular */
'use strict';

/**
 * Main App Module
 */

function LoginBaseCtrl($scope, $http, $timeout) {
    $scope.username = "";
    $scope.password = "";
    $scope.otp = "";
    $scope.error = "";
    $scope.otp_request = false;
    $scope.alternate_login = true;
    $scope.signup_mode = false;
    $scope.u2f_response = "";
    $scope.signed_up = false;

    $scope.switch_to_otp = function(){
        $scope.error = '';
        $scope.otp_request = true;
        $scope.u2f_request = false;
        $timeout(function(){$('#inputOTP').focus()}, 100);
    };

    $scope.switch_to_userpass = function(){
        $scope.error = '';
        $scope.username = "";
        $scope.alternate_login=true;
        $timeout(function(){$('#inputUser').focus()}, 100);
    };

    $scope.switch_to_signup = function(){
        $scope.error = '';
        $scope.username = "";
        $scope.signup_mode=true;
        $timeout(function(){$('#inputUser').focus()}, 100);
    };

    //Signup via API
    $scope.signup = function () {
        $scope.error = '';
        $scope.loading = true;

        $http({
            method: 'POST',
            url: "/api/v4/auth/signup/",
            data: {
                user: $scope.username_signup,
                password: $scope.password_signup,
                password_confirm: $scope.password_signup_confirm,
                email: $scope.email_signup}
            })
            .success(function () {
                $scope.signed_up = true;
            })
            .error(function (data) {
                $scope.error = data.api_error_message;
                $scope.loading = false;
            });
    };

    //Login via API
    $scope.login = function () {
        $scope.error = '';
        $scope.loading = true;
        let password = $scope.password;

        $http({
            method: 'POST',
            url: "/api/v4/auth/login/",
            data: {user: $scope.username, password: password, otp: $scope.otp, u2f_response: $scope.u2f_response}
        })
        .success(function () {
            window.location = $scope.next;
        })
        .error(function (data) {
            if (data.api_error_message === 'Wrong U2F Security Token'){
                if ($scope.u2f_request){
                    $scope.error = data.api_error_message;
                }
                else{
                    $scope.u2f_request = true;
                    $scope.otp_request = false;
                }

                $http({
                    method: 'GET',
                    url: "/api/v4/u2f/sign/" + $scope.username + "/"
                })
                .success(function (data) {
                    $scope.loading = false;
                    u2f.sign(data.api_response.appId, data.api_response.challenge, data.api_response.registeredKeys,
                        function(deviceResponse) {
                            if (deviceResponse.errorCode === undefined){
                                $scope.u2f_response = deviceResponse;
                                $timeout(function(){
                                    $scope.login();
                                }, 100);
                            }
                            else{
                                $timeout(function(){
                                    $scope.error = "Invalid Security Token";
                                    $scope.u2f_request = false;
                                }, 100);
                            }
                        });
                })
                .error(function (data) {
                    $scope.error = data.api_error_message;
                    $scope.loading = false;
                });

            }
            else if (data.api_error_message === 'Wrong OTP token'){
                if ($scope.otp_request){
                    $scope.error = data.api_error_message;
                }
                else{
                    $scope.otp_request = true;
                    $scope.u2f_request = false;
                }
                $scope.loading = false;
                $scope.otp = "";
                $timeout(function(){$('#inputOTP').focus()}, 100);
            }
            else {
                $scope.error = data.api_error_message;
                $scope.loading = false;
            }
        });
    };

    //Load current_user from datastore
    $scope.start = function () {};
}

let app = angular.module('app', []);
app.controller('ALController', LoginBaseCtrl);
