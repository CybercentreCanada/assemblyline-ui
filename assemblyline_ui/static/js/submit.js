/* global angular */
'use strict';

/**
 * Main App Module
 */
let uuid = null;

function generateUUID(file) {
    let relativePath = file.relativePath || file.webkitRelativePath || file.fileName || file.name;

    if (uuid === null) {
        let d = new Date().getTime();
        uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            let r = (d + Math.random() * 16) % 16 | 0;
            d = Math.floor(d / 16);
            return (c === 'x' ? r : (r & 0x7 | 0x8)).toString(16);
        });
    }

    return uuid + "_" + file.size + '_' + relativePath.replace(/[^0-9a-zA-Z_-]/img, '');
}

function SubmitBaseCtrl($scope, $http, $timeout) {
    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };
    $scope.submission_url = "";

    $scope.receiveClassification = function (classification) {
        $scope.params.classification = classification;
    };

    $scope.submit_url = function(url){
        let urlParseRE = /^(((([^:\/#?]+:)?(?:(\/\/)((?:(([^:@\/#?]+)(?::([^:@\/#?]+))?)@)?(([^:\/#?\]\[]+|\[[^\/\]@#?]+])(?::([0-9]+))?))?)?)?((\/?(?:[^\/?#]+\/+)*)([^?#]*)))?(\?[^#]+)?)(#.*)?/;
        let matches = urlParseRE.exec(url);

        if (matches[15] === undefined || matches[15] === ''){
            matches[15] = "file";
        }

        let data = {
            name: matches[15],
            url: url,
            ui_params: $scope.params
        };

        $scope.loading = true;
        $http({
            method: 'POST',
            url: "/api/v4/submit/",
            data: data
        })
        .success(function (data) {
            window.location = "/submission_detail.html?new&sid=" + data.api_response.sid;
        })
        .error(function (data, status, headers, config) {
            if (status === 401){
                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                return;
            }

            if (data === "") {
                return;
            }

            $scope.loading = false;

            let message = "";
            if (data.api_error_message) {
                message = data.api_error_message;
            }
            else {
                message = config.url + " (" + status + ")";
            }
            swal({
                    title: "Submission failed!",
                    text: message,
                    type: "error",
                    showCancelButton: false,
                    confirmButtonColor: "#D0D0D0",
                    confirmButtonText: "Close",
                    closeOnConfirm: true
                });
        });


    };

    $scope.prepare_transfer = function (url) {
        let type = "file(s)";
        if (url !== undefined){
            type = "url";
        }
        if ($scope.user.c12n_enforcing) {
            swal({
                    title: $scope.params.classification,
                    text: "\n\nAre you sure this is the right classification for your " + type + "?\n\n",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Yes, submit this!",
                    closeOnConfirm: true
                },
                function () {
                    $timeout(function () {
                        $scope.check_external(url);
                    }, 250)
                });
        }
        else {
            $scope.check_external(url);
        }
    };

    $scope.check_external = function (url) {
        let type = "file(s)";
        if (url !== undefined){
            type = "url";
        }
        let raise_warning = false;
        for (let i = 0; i < $scope.params.services.length; i++) {
            for (let x = 0; x < $scope.params.services[i].services.length; x++) {
                if ($scope.params.services[i].services[x].is_external && $scope.params.services[i].services[x].selected) {
                    raise_warning = true;
                    break;
                }
            }
        }

        if (raise_warning) {
            swal({
                    title: "External Submission!",
                    text: "\n\nYou are about to submit your " + type + " to a service outside of our infrastructure.\n\nThis may take several minutes...\n\n",
                    type: "warning",
                    showCancelButton: true,
                    confirmButtonColor: "#d9534f",
                    confirmButtonText: "Deselect external services",
                    cancelButtonText: "Continue",
                    closeOnConfirm: true,
                    closeOnCancel: true
                },
                function () {
                    for (let i = 0; i < $scope.params.services.length; i++) {
                        for (let x = 0; x < $scope.params.services[i].services.length; x++) {
                            if ($scope.params.services[i].services[x].is_external && $scope.params.services[i].services[x].selected) {
                                $scope.params.services[i].selected = false;
                                $scope.params.services[i].services[x].selected = false;
                            }
                        }
                    }
                    if (type === "url"){
                        $scope.submit_url(url);
                    }
                    else{
                        $scope.start_transfer();
                    }
                },
                function () {
                    if (type === "url"){
                        $scope.submit_url(url);
                    }
                    else{
                        $scope.start_transfer();
                    }
                });
        }
        else {
            if (type === "url"){
                $scope.submit_url(url);
            }
            else{
                $scope.start_transfer();
            }
        }
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';
    $scope.loading = false;
    $scope.user = null;
    $scope.obj = {};
    $scope.started = false;

    //File transfer letiables/Functions
    $scope.transfer_started = false;

    $scope.start_transfer = function () {
        $scope.transfer_started = true;
        $scope.obj.flow.on('complete', function () {
            if ($scope.obj.flow.files.length === 0){
                return;
            }

            for (let x = 0; x < $scope.obj.flow.files.length; x++) {
                if ($scope.obj.flow.files[x].error) {
                    return;
                }
            }
            if (!$scope.started){
                $scope.started = true;
                $http({
                    method: 'POST',
                    url: "/api/v4/ui/start/" + uuid + "/",
                    data: $scope.params
                })
                    .success(function (data) {
                        window.location = "/submission_detail.html?new&sid=" + data.api_response.sid;
                    })
                    .error(function (data, status, headers, config) {
                        if (status === 401){
                            window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                            return;
                        }

                        if (data === "") {
                            return;
                        }

                        let message = "";
                        if (data.api_error_message) {
                            message = data.api_error_message;
                        }
                        else {
                            message = config.url + " (" + status + ")";
                        }
                        swal({
                                title: "Submission failed!",
                                text: message,
                                type: "error",
                                showCancelButton: false,
                                confirmButtonColor: "#D0D0D0",
                                confirmButtonText: "Close",
                                closeOnConfirm: true
                            });

                        $scope.reset_transfer();
                        uuid = null;
                    });
            }

        });
        $scope.obj.flow.upload();
    };

    $scope.reset_transfer = function () {
        $scope.transfer_started = false;
        $scope.started = false;
        $scope.obj.flow.cancel();
        $scope.obj.flow.off('complete');
    };

    //Sliding menu
    $scope.params = null;
    $scope.params_bck = null;

    $scope.serviceSelectionReset = function ($event) {
        $event.stopImmediatePropagation();
        for (let i = 0; i < $scope.params.services.length; i++) {
            $scope.params.services[i].selected = $scope.params_bck.services[i].selected;
            for (let x = 0; x < $scope.params.services[i].services.length; x++) {
                $scope.params.services[i].services[x].selected = $scope.params_bck.services[i].services[x].selected;
            }
        }
    };

    $scope.serviceSelectionNone = function ($event) {
        $event.stopImmediatePropagation();
        for (let i = 0; i < $scope.params.services.length; i++) {
            $scope.params.services[i].selected = false;
            for (let x = 0; x < $scope.params.services[i].services.length; x++) {
                $scope.params.services[i].services[x].selected = false;
            }
        }
    };

    $scope.serviceSelectionAll = function ($event) {
        $event.stopImmediatePropagation();
        for (let i = 0; i < $scope.params.services.length; i++) {
            $scope.params.services[i].selected = true;
            for (let x = 0; x < $scope.params.services[i].services.length; x++) {
                $scope.params.services[i].services[x].selected = true;
            }
        }
    };

    $scope.toggleCBService = function (group_name) {
        for (let i = 0; i < $scope.params.services.length; i++) {
            if ($scope.params.services[i].name === group_name) {
                $scope.params.services[i].selected = true;
                for (let x = 0; x < $scope.params.services[i].services.length; x++) {
                    if (!$scope.params.services[i].services[x].selected) {
                        $scope.params.services[i].selected = false;
                        break;
                    }
                }
                break;
            }
        }
    };

    $scope.toggleCBGroup = function (group_name, selected) {
        for (let i = 0; i < $scope.params.services.length; i++) {
            if ($scope.params.services[i].name === group_name) {
                for (let x = 0; x < $scope.params.services[i].services.length; x++) {
                    $scope.params.services[i].services[x].selected = selected;
                }
                break;
            }
        }
    };

    //Load params from datastore
    $scope.start = function () {
        $scope.loading = true;
        $http({
            method: 'GET',
            url: "/api/v4/user/settings/" + $scope.user.uname + "/"
        })
            .success(function (data) {
                $scope.loading = false;
                let temp_param = jQuery.extend(true, {}, data.api_response);
                let temp_param_bck = jQuery.extend(true, {}, data.api_response);

                $scope.params = temp_param;
                $scope.params_bck = temp_param_bck;
            })
            .error(function (data, status, headers, config) {
                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "") {
                    return;
                }

                $scope.loading = false;

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
            });
    };
}

function flowFactory(flowFactoryProvider) {
    flowFactoryProvider.defaults = {
        target: '/api/v4/ui/flowjs/',
        permanentErrors: [412, 404, 500],
        maxChunkRetries: 1,
        chunkRetryInterval: 2000,
        simultaneousUploads: 4,
        generateUniqueIdentifier: generateUUID
    };
    flowFactoryProvider.on('fileError', function (event) {
        try{
            let data = JSON.parse(arguments[1]);
            if (data.hasOwnProperty("api_status_code")){
                if (data.api_status_code === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                }
            }
        }
        catch (ex){}
    });
}

let app = angular.module('app', ['search', 'flow', 'utils', 'ui.bootstrap']);
app.config(flowFactory);
app.controller('ALController', SubmitBaseCtrl);
