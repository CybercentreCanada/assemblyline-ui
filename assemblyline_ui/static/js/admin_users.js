/* global angular */
'use strict';

/**
 * Main App Module
 */

function AdminUserBaseCtrl($scope, $http, $timeout) {
    //Parameters vars
    $scope.user_list = null;
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.current_user = null;
    $scope.started = false;
    $scope.editmode = true;

    $scope.filtered = false;
    $scope.filter = "";

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    //Error handling
    $scope.error = '';
    $scope.success = '';

    //Pager vars
    $scope.show_pager_add = true;
    $scope.pager_add = function () {
        $scope.reset_error_ctrls();
        $scope.editmode = false;
        $scope.current_user = {
            avatar: null,
            groups: ["USERS"],
            is_active: true,
            type: ['user'],
            classification: classification_definition.UNRESTRICTED,
            name: "",
            uname: "",
            api_quota: 10,
            submission_quota: 5
        };
        $scope.current_user.new_pass = null;
        $scope.error = '';
        $scope.success = '';
        $('#avatar').attr("src", "/static/images/user_default.png");
        $("#myModal").modal('show');
    };

    $scope.is_admin = function(){
        return $scope.user.type.indexOf('admin') !== -1
    };

    $scope.maximum_classification = true;
    $scope.receiveClassification = function (classification) {
        $scope.current_user.classification = classification;
    };

    $scope.pager_btn_text = "Add User";
    $scope.total = null;
    $scope.offset = 0;
    $scope.rows = 25;
    $scope.searchText = "";
    $scope.$watch('searchText', function () {
        if ($scope.started && $scope.searchText !== undefined && $scope.searchText != null) {
            if ($scope.searchText === "") {
                $scope.filter = "";
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

    //User editing
    $("#myModal").on('hidden.bs.modal', function () {
        $("#uname").removeClass("has-error");
        $("#uname_lbl").text("User ID")
    });

    $scope.reveal_show = function () {
        let ctrl = $("#pwd");
        ctrl.attr('type', 'text');
    };

    $scope.reveal_hide = function () {
        let ctrl = $("#pwd");
        ctrl.attr('type', 'password');
    };

    $scope.delUser = function (user) {
        swal({
                title: "Delete User?",
                text: "You are about to delete the current user. Are you sure?",
                type: "warning",
                showCancelButton: true,
                confirmButtonColor: "#d9534f",
                confirmButtonText: "Yes, delete it!",
                closeOnConfirm: true
            },
            function () {
                $scope.do_delUser(user);
            })
    };

    $scope.do_delUser = function (user) {
        console.log("Delete", user);
        $("#myModal").modal('hide');
        $scope.loading_extra = true;

        $http({
            method: 'DELETE',
            url: "/api/v4/user/" + user.uname + "/"
        })
            .success(function () {
                $scope.loading_extra = false;
                $scope.success = "User " + user.uname.toUpperCase() + " successfully removed!";
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
                $scope.started = true;

            });
    };

    $scope.editUser = function (user) {
        $scope.reset_error_ctrls();
        $scope.editmode = true;

        $scope.error = '';
        $scope.success = '';
        $scope.loading_extra = true;

        $http({
            method: 'GET',
            url: "/api/v4/user/" + user.uname + "/?load_avatar=true"
        })
            .success(function (data) {
                $scope.loading_extra = false;
                $scope.current_user = data.api_response;
                $scope.current_user.new_pass = null;
                if ($scope.current_user.avatar != null) {
                    $('#avatar').attr("src", $scope.current_user.avatar);
                }
                else {
                    $('#avatar').attr("src", "/static/images/user_default.png");
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

    //Save params
    $scope.save = function () {
        $scope.reset_error_ctrls();
        $scope.loading_extra = true;
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'POST',
            url: "/api/v4/user/" + $scope.current_user.uname + "/",
            data: $scope.current_user
        })
            .success(function () {
                $scope.loading_extra = false;
                $("#myModal").modal('hide');
                $scope.success = "User " + $scope.current_user.uname.toUpperCase() + " successfully updated!";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                let ctrl;
                $scope.loading_extra = false;

                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (status === 400) {
                    ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Username already exists");
                    return;
                }

                if (status === 412) {
                    ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Invalid characters used in the User ID");
                    return;
                }

                if (status === 469) {
                    let pass_ctrl = $("#new_pass");
                    pass_ctrl.addClass("has-error");
                    pass_ctrl.find("input").select();
                    pass_ctrl.find('error').text("* " + data.api_error_message);
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

    $scope.toggle_active = function(){
        $scope.current_user.is_active = !$scope.current_user.is_active;
    };

    $scope.toggle_type = function(type){
        if ($scope.current_user.type.indexOf(type) !== -1){
            $scope.current_user.type.splice($scope.current_user.type.indexOf(type), 1);
        }
        else {
            $scope.current_user.type.push(type);
        }
    };

    $scope.reset_error_ctrls = function () {
        let ctrl = $("#uname");
        ctrl.removeClass("has-error");
        ctrl.find("error").text("");
        let pass_ctrl = $("#new_pass");
        pass_ctrl.removeClass("has-error");
        pass_ctrl.find("error").text("");
    };

    $scope.add = function () {
        $scope.reset_error_ctrls();
        $scope.error = '';
        $scope.success = '';

        $http({
            method: 'PUT',
            url: "/api/v4/user/" + $scope.current_user.uname + "/",
            data: $scope.current_user
        })
            .success(function () {
                if (!$scope.editmode) $scope.user_list.push($scope.current_user);
                $("#myModal").modal('hide');
                $scope.success = "User " + $scope.current_user.uname.toUpperCase() + " successfully added!";
                $timeout(function () {
                    $scope.success = "";
                    $scope.load_data();
                }, 2000);
            })
            .error(function (data, status, headers, config) {
                let ctrl;
                $scope.loading_extra = false;

                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (status === 400) {
                    ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Username already exists");
                    return;
                }

                if (status === 412) {
                    ctrl = $("#uname");
                    ctrl.addClass("has-error");
                    ctrl.find("input").select();
                    ctrl.find("error").text("* Invalid characters used in the User ID");
                    return;
                }

                if (status === 469) {
                    let pass_ctrl = $("#new_pass");
                    pass_ctrl.addClass("has-error");
                    pass_ctrl.find("input").select();
                    pass_ctrl.find('error').text("* " + data.api_error_message);
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
        $scope.load_data();
    };

    //Pager methods
    $scope.load_data = function () {
        $scope.loading_extra = true;

        $http({
            method: 'GET',
            url: "/api/v4/user/list/?offset=" + $scope.offset + "&rows=" + $scope.rows + "&query=" + encodeURIComponent($scope.filter)
        })
            .success(function (data) {
                $scope.loading_extra = false;

                $scope.user_list = data.api_response.items;
                $scope.total = data.api_response.total;

                $scope.pages = $scope.pagerArray();
                $scope.started = true;

                $scope.filtered = $scope.filter !== "";
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;

                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "" || data === null || status === 400) {
                    $scope.user_list = [];
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
}

var app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', AdminUserBaseCtrl);
