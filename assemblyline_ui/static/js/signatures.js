/* global angular */
'use strict';

/**
 * Main App Module
 */
function ServiceBaseCtrl($scope, $http, $timeout) {
    //Parameters lets
    $scope.signature_list = null;
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.current_signature = null;
    $scope.current_signature_id = null;
    $scope.organisation = "assemblyline";
    $scope.started = false;
    $scope.editmode = true;
    $scope.state_changed = false;
    $scope.signature_changed = false;
    $scope.current_signature_state = "TESTING";
    $scope.filtered = false;
    $scope.filter = "id:*";
    $scope.non_editable = [
        'al_imported_by',
        'al_state_change_date',
        'al_state_change_user',
        'creation_date',
        'last_modified',
        'last_saved_by',
        'modification_date'
    ];

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    //pager dependencies
    $scope.total = null;
    $scope.offset = 0;
    $scope.rows = 25;
    $scope.searchText = "";
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

    $scope.receiveClassification = function (classification) {
        $scope.current_signature.classification = classification;
    };

    $scope.del = function () {
        swal({
                title: "Delete signature?",
                text: "You are about to delete the current signature. Are you sure?",
                type: "warning",
                showCancelButton: true,
                confirmButtonColor: "#d9534f",
                confirmButtonText: "Yes, delete it!",
                closeOnConfirm: true
            },
            function () {
                $scope.do_del();
            })
    };

    $scope.do_del = function () {
        $scope.loading_extra = true;
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'DELETE',
            url: "/api/v4/signature/" + $scope.current_signature_id + "/"
        })
            .success(function () {
                $scope.loading_extra = false;
                $("#myModal").modal('hide');
                $scope.success = "Signature '" + $scope.current_signature_id + "' successfully deleted!";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
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
                scroll(0, 0);
            });
    };

    let myModal = $("#myModal");
    myModal.on('shown.bs.modal', function () {
        $scope.$apply(function () {
            $scope.state_changed = false;
            $scope.signature_changed = false;
            $scope.current_signature_state = $scope.current_signature.status;
        });
    });

    myModal.on('show.bs.modal', function () {
        $scope.sig_temp_key = null;
        $scope.sig_temp_val = null;

        if ($scope.editmode) {
            $("#preview").addClass('active');
            $("#preview_tab").addClass('active');
            $("#state").removeClass('active');
            $("#state_tab").removeClass('active');
        }
        else {
            $("#preview").removeClass('active');
            $("#preview_tab").removeClass('active');
            $("#state").removeClass('active');
            $("#state_tab").removeClass('active');
        }

    });

    $scope.editSignature = function (sid) {
        $scope.loading_extra = true;
        $scope.editmode = true;
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'GET',
            url: "/api/v4/signature/" + sid + "/"
        })
            .success(function (data) {
                $scope.loading_extra = false;
                $scope.current_signature_id = sid;
                $scope.current_signature = data.api_response;
                $("#myModal").modal('show');
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
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

    $scope.change_state = function (new_status) {
        $http({
            method: 'GET',
            url: "/api/v4/signature/change_status/" + $scope.current_signature_id + "/" + new_status + "/"
        })
            .success(function () {
                $("#myModal").modal('hide');
                $scope.success = "Status of signature " + $scope.current_signature_id + " successfully changed to " + new_status + ". Changes will take effect in 2 minutes...";
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

    //Load params from datastore
    $scope.start = function () {
        $scope.load_data();
    };

    //Page traversing
    $scope.load_data = function () {
        $scope.loading_extra = true;

        $http({
            method: 'GET',
            url: "/api/v4/search/signature/?offset=" + $scope.offset + "&rows=" + $scope.rows + "&query=" + encodeURIComponent($scope.filter)
        })
            .success(function (data) {
                $scope.loading_extra = false;

                $scope.signature_list = data.api_response.items;
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

                if (data === "" || status === 400) {
                    $scope.signature_list = [];
                    $scope.total = 0;
                    $scope.filtered = true;
                    $scope.pages = $scope.pagerArray();
                    $scope.started = true;
                    return;
                }

                if (data.api_error_message) {
                    $scope.error = data.api_error_message;
                }
                else {
                    $scope.error = config.url + " (" + status + ")";
                }
                $scope.started = true;

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
app.controller('ALController', ServiceBaseCtrl);

