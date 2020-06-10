/* global angular */
'use strict';

/**
 * Main App Module
 */
function SignatureDetailBaseCtrl($scope, $http, $timeout) {
    //Parameters lets
    $scope.user = null;
    $scope.options = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.sid = null;
    $scope.sig_temp_key = null;
    $scope.sig_temp_val = null;
    $scope.current_signature = null;
    $scope.editmode = true;
    $scope.organisation = "assemblyline";
    $scope.state_changed = false;
    $scope.signature_changed = false;
    $scope.current_signature_state = "TESTING";

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    $scope.receiveClassification = function (classification) {
        $scope.current_signature.classification = classification;
    };

    $scope.change_state = function (new_status) {
        $http({
            method: 'GET',
            url: "/api/v4/signature/change_status/" + $scope.sid + "/" + new_status + "/"
        })
            .success(function () {
                $("#myModal").modal('hide');
                $scope.success = "Status of signature " + $scope.sid + " successfully changed to " + new_status + ".";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);

            })
            .error(function (data, status, headers, config) {
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
            });
    };

    $scope.set_state_change = function () {
        $scope.state_changed = true;
    };

    //load data
    $scope.start = function () {
        $scope.load_data();
    };

    $scope.load_data = function () {
        $http({
            method: 'GET',
            url: "/api/v4/signature/" + $scope.sid + "/"
        })
            .success(function (data) {
                $scope.current_signature = data.api_response;
                $scope.current_signature_state = data.api_response.status;
            })
            .error(function (data, status, headers, config) {
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
            });
    };


    $scope.insertTab = function (e){
        let kC = e.keyCode ? e.keyCode : e.charCode ? e.charCode : e.which;
        let o = e.target;
        if (kC === 9 && !e.shiftKey && !e.ctrlKey && !e.altKey)
        {
            let oS = o.scrollTop;
            if (o.setSelectionRange)
            {
                let sS = o.selectionStart;
                let sE = o.selectionEnd;
                o.value = o.value.substring(0, sS) + "    " + o.value.substr(sE);
                o.setSelectionRange(sS + 4, sS + 4);
                o.focus();
            }
            else if (o.createTextRange)
            {
                document.selection.createRange().text = "    ";
                e.returnValue = false;
            }
            o.scrollTop = oS;
            if (e.preventDefault)
            {
                e.preventDefault();
            }
            return false;
        }
        return true;
    };

}

let app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', SignatureDetailBaseCtrl);

