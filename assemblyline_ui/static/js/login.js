/* global angular */
'use strict';

/**
 * Main App Module
 */

function toArrayBuffer(data){
    let uint8Array = new Uint8Array(data.length);
    for (let i = 0; i < uint8Array.length; i++){
        uint8Array[i] = data[i];
    }

    return uint8Array;
}

function LoginBaseCtrl($scope, $http, $timeout) {
    $scope.username = "";
    $scope.password = "";
    $scope.otp = "";
    $scope.error = "";
    $scope.oauth_error = "";
    $scope.oauth_token = "";
    $scope.oauth_validation = false;
    $scope.otp_request = false;
    $scope.up_login = true;
    $scope.signup_mode = false;
    $scope.security_token_request = false;
    $scope.webauthn_auth_resp = "";
    $scope.signed_up = false;
    $scope.providers = [];

    $scope.switch_to_otp = function(){
        $scope.error = '';
        $scope.otp_request = true;
        $scope.security_token_request = false;
        $timeout(function(){$('#inputOTP').focus()}, 100);
    };

    $scope.switch_user = function(){
        $scope.error = '';
        $scope.oauth_error = '';
        $scope.username = "";
        $scope.oauth_validation=false;
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
                $scope.loading = false;
                $scope.signed_up = true;
            })
            .error(function (data) {
                $scope.error = data.api_error_message;
                $scope.loading = false;
            });
    };

    //Login via API
    $scope.login = function (oauth_provider) {
        if (oauth_provider === undefined){
            oauth_provider = "";
        }

        $scope.error = '';
        $scope.loading = true;
        let password = $scope.password;

        $http({
            method: 'POST',
            url: "/api/v4/auth/login/",
            data: {
                user: $scope.username,
                password: password,
                otp: $scope.otp,
                webauthn_auth_resp: $scope.webauthn_auth_resp,
                oauth_provider: oauth_provider,
                oauth_token: $scope.oauth_token
            }
        })
        .success(function () {
            window.location = $scope.next;
        })
        .error(function (data) {
            if (data.api_error_message === 'Wrong Security Token'){
                if ($scope.security_token_request){
                    $scope.error = data.api_error_message;
                }
                else{
                    $scope.security_token_request = true;
                    $scope.otp_request = false;
                }

                $http({
                    method: 'GET',
                    url: "/api/v4/webauthn/authenticate/begin/" + $scope.username + "/"
                })
                .success(function (data) {
                    $scope.loading = false;
                    let arrayData = toArrayBuffer(data.api_response);
                    const options = CBOR.decode(arrayData.buffer);
                    navigator.credentials.get(options).then(
                        function(assertion) {
                            let assertion_data = CBOR.encode({
                                "credentialId": new Uint8Array(assertion.rawId),
                                "authenticatorData": new Uint8Array(assertion.response.authenticatorData),
                                "clientDataJSON": new Uint8Array(assertion.response.clientDataJSON),
                                "signature": new Uint8Array(assertion.response.signature)
                            });

                            $scope.webauthn_auth_resp = Array.from(new Uint8Array(assertion_data));
                                $timeout(function(){
                                    $scope.login();
                                }, 100);

                        }).catch(
                        function(ex) {
                            $timeout(function () {
                                $scope.switch_to_otp();
                                $scope.error = "Security token was invalid or operation was cancelled. Try with OTP instead?";
                            }, 100);
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
                    $scope.security_token_request = false;
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

String.prototype.toProperCase = function () {
    return this.replace(/\w\S*/g, function (txt) {
        let full_upper = ["ad", "ip", "id", "al", "ts", "md5", "sha1", "sha256", "cc", "bcc", "smtp", "ftp", "http", "pe", "db", "ui", "ttl", "vm", "os", "uid", 'ioc'];
        let full_lower = ["to", "as", "use"];

        if (full_upper.indexOf(txt.toLowerCase()) !== -1) {
            return txt.toUpperCase();
        }

        if (full_lower.indexOf(txt.toLowerCase()) !== -1) {
            return txt.toLowerCase();
        }

        return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
    });
};

app.filter('titleCase', function () {
    return function (input) {
        if (input === null || input === undefined){
            return input
        }
        input = input.replace(/-/g, " ").replace(/_/g, " ").replace(/\./g, " ");
        return input.toProperCase();
    }
});