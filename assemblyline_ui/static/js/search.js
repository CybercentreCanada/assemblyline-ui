/* global angular */
'use strict';

/**
 * Main App Module
 */

function SearchBaseCtrl($scope, $http, $timeout) {
    //Parameters lets
    $scope.user = null;
    $scope.loading = false;
    $scope.loading_extra = false;
    $scope.file_list = null;
    $scope.submission_list = null;
    $scope.signature_list = null;
    $scope.result_list = null;
    $scope.alert_list = null;
    $scope.query = null;
    $scope.new_query = null;
    $scope.invalid_query = null;
    $scope.export_btn = false;
    $scope.search_scope = "all";
    $scope.scoped_search = false;
    $scope.use_archive = true;
    $scope.buckets = ["submission", "file", "result", "signature", "alert"];
    $scope.scopes = [
        {value: "all", name: "All Indexes"},
        {value: "alert", name: "Alert index"},
        {value: "file", name: "File index"},
        {value: "result", name: "Result index"},
        {value: "signature", name: "Signature index"},
        {value: "submission", name: "Submission index"}];

    //DEBUG MODE
    $scope.debug = false;
    $scope.showParams = function () {
        console.log("Scope", $scope)
    };

    $scope.switch_search_scope = function (new_scope){
        $scope.search_scope = new_scope;
    };

    $scope.dump = function (obj) {
        return angular.toJson(obj, true);
    };


    $scope.enable_archive = function(){
        if (!$scope.use_archive){
            $scope.use_archive = true;
            $scope.reset();
        }
    };

    $scope.disable_archive = function(){
        if ($scope.use_archive){
            $scope.use_archive = false;
            $scope.reset();
        }
    };

    $scope.getKeys = function (o) {
        try {
            return Object.keys(o);
        } catch (ex) {
            return [];
        }
    };

    $scope.get_default_view = function(){
        if ($scope.settings.submission_view === "report"){
            return 'report';
        }
        else{
            return 'submission_detail';
        }
    };

    //Error handling
    $scope.error = '';

    $scope.show_export_btn = function (show) {
        $scope.export_btn = show;
    };

    //pager dependencies
    $scope.started = false;
    $scope.cur_list = $scope.submission_list;
    $scope.total = null;
    $scope.offset = 0;
    $scope.rows = 25;
    $scope.disable_pager_filter = true;
    $scope.searchText = "";

    $scope.search_bucket = function(bucket, data, callback){
        $scope.loading_extra = true;
        $http({
                method: 'POST',
                url: "/api/v4/search/" + bucket + "/",
                data: data
            })
            .success(function (data) {
                $scope.loading_extra = false;
                callback(bucket, data.api_response)
            })
            .error(function (data, status, headers, config) {
                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "") {
                    return;
                }

                $scope.loading_extra = false;

                if (data.api_error_message.indexOf("Rewrite first") !== -1 && !$scope.scoped_search){
                    callback(bucket, {
                        items: [],
                        offset: 0,
                        rows: $scope.rows,
                        total: 0
                    })
                }
                else if (status === 400) {
                    $timeout(function () {
                        $("#search-term").addClass("has-error");
                        let sb = $("#search-box");
                        sb.select();
                        sb.focus();
                    }, 0);

                    $scope.invalid_query = data.api_error_message;
                }
                else {
                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                }
                $scope.started = true;
            });
    };

    $scope.show_tab = function(tab){
        for (let tab_id in $scope.buckets){
            let current_tab = $scope.buckets[tab_id];
            if (tab === current_tab){
                $('#' + current_tab + '_tab').addClass("active");
                $('#' + current_tab).addClass("active");
            }
            else{
                $('#' + current_tab + '_tab').removeClass("active");
                $('#' + current_tab).removeClass("active");
            }
        }

    };

    $scope.search_callback = function (bucket, data){
        data.bucket = bucket;
        $scope[bucket + "_list"] = data;

        if (!$scope.scoped_search && ($scope.submission_list !== null || $scope.alert_list !== null
            || $scope.file_list !== null || $scope.signature_list !== null || $scope.result_list !== null)) {
            if ($scope.submission_list !== null && $scope.submission_list.total !== 0) {
                $scope.show_tab('submission');
                $scope.total = $scope.submission_list.total;
                $scope.cur_list = $scope.submission_list;
                $scope.export_btn = false;
            } else if ($scope.file_list !== null && $scope.file_list.total !== 0) {
                $scope.show_tab('file');
                $scope.cur_list = $scope.file_list;
                $scope.total = $scope.file_list.total;
                $scope.export_btn = false;
            } else if ($scope.result_list !== null && $scope.result_list.total !== 0) {
                $scope.show_tab('result');
                $scope.cur_list = $scope.result_list;
                $scope.total = $scope.result_list.total;
                $scope.export_btn = false;
            } else if ($scope.signature_list !== null && $scope.signature_list.total !== 0) {
                $scope.show_tab('signature');
                $scope.cur_list = $scope.signature_list;
                $scope.total = $scope.signature_list.total;
                $scope.export_btn = $scope.total > 0;
            } else if ($scope.alert_list !== null && $scope.alert_list.total !== 0) {
                $scope.show_tab('alert');
                $scope.cur_list = $scope.alert_list;
                $scope.total = $scope.alert_list.total;
                $scope.export_btn = false;
            }
            $scope.pages = $scope.pagerArray();
            $scope.started = true;
        }
        else if ($scope.scoped_search){
            $scope.show_tab($scope.search_scope);
            $scope.total = $scope[$scope.search_scope + "_list"].total;
            $scope.cur_list = $scope[$scope.search_scope + "_list"];
            $scope.export_btn = $scope.search_scope === 'signature';
            $scope.pages = $scope.pagerArray();
            $scope.started = true;
       }
    };

    //Load params from datastore
    $scope.start = function () {
        if ($scope.query == null || $scope.query === "") {
            return;
        }

        $scope.new_query = $scope.query;

        $timeout(function (){
            let data = {};
            data['query'] = $scope.query;
            data['offset'] = $scope.offset;
            data['rows'] = $scope.rows;
            data['use_archive'] = $scope.use_archive;

            if (!$scope.scoped_search){
                for (let bucket in $scope.buckets) {
                    $scope.search_bucket($scope.buckets[bucket], data, $scope.search_callback)
                }
            }
            else{
                $scope.search_bucket($scope.search_scope, data, $scope.search_callback)
            }

        }, 50);
    };

    $scope.reset = function (){
        $scope.file_list = null;
        $scope.submission_list = null;
        $scope.signature_list = null;
        $scope.result_list = null;
        $scope.alert_list = null;
        $scope.export_btn = false;
        $scope.invalid_query = null;
        $("#search-term").removeClass("has-error");
        $scope.query = this.new_query;
        $scope.search_scope = this.search_scope;
        $scope.scoped_search = $scope.search_scope !== 'all';
        $scope.start();
    };

    $scope.load_data = function () {
        if ($scope.query == null || $scope.query === "") {
            return;
        }

        $scope.loading_extra = true;
        let data = {};
        data['query'] = $scope.query;
        data['offset'] = $scope.offset;
        data['rows'] = $scope.rows;
        data['use_archive'] = $scope.use_archive;

        $http({
            method: 'POST',
            url: "/api/v4/search/" + $scope.cur_list.bucket + "/",
            data: data
        })
        .success(function (data, status) {
            $scope.loading_extra = false;
            data.api_response.bucket = $scope.cur_list.bucket;

            if (status === 401){
                window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                return;
            }

            if ($scope.cur_list.bucket === "file") {
                $scope.file_list = data.api_response;
            }
            else if ($scope.cur_list.bucket === "submission") {
                $scope.submission_list = data.api_response;
            }
            else if ($scope.cur_list.bucket === "result") {
                $scope.result_list = data.api_response;
            }
            else if ($scope.cur_list.bucket === "signature") {
                $scope.signature_list = data.api_response;
            }
            else if ($scope.cur_list.bucket === "alert") {
                $scope.alert_list = data.api_response;
            }

            $scope.total = data.api_response.total;
            $scope.pages = $scope.pagerArray();
            $scope.started = true;
        })
        .error(function (data, status, headers, config) {
            if (data === "") {
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
}

let app = angular.module('app', ['utils', 'search', 'ngAnimate', 'ui.bootstrap']);
app.controller('ALController', SearchBaseCtrl);
