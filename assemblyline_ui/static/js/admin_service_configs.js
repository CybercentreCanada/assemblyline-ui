/* global angular */
'use strict';

/**
 * Main App Module
 */
let app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $http, $timeout) {
        //Parameters vars
        $scope.service_list = null;
        $scope.user = null;
        $scope.loading = false;
        $scope.loading_extra = false;
        $scope.current_service = null;
        $scope.current_source = null;
        $scope.current_docker_config_name = null;
        $scope.current_docker_config_name_old = null;
        $scope.update_data = {};
        $scope.started = false;
        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';
        $scope.yaml = '';

        $scope.obj_len = function (o) {
            if (o === undefined || o == null) return 0;
            return Object.keys(o).length;
        };

        $scope.typeOf = function (val) {
            return typeof val;
        };

        $scope.receiveClassification = function (classification) {
            if ($scope.current_source !== null){
                $scope.current_source.default_classification = classification;
            }
            else {
                $scope.current_service.default_result_classification = classification;
            }
        };

        $scope.show_add_service = function () {
            $scope.yaml = '';
            $("#serviceAddModal").modal('show');
        };

        $scope.add_service = function () {
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.success = '';

            $http({
                method: 'PUT',
                url: "/api/v4/service/",
                data: $scope.yaml
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $("#serviceAddModal").modal('hide');
                    $scope.success = "Service " + data.api_response.service_name + " successfully added!";
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

                    if (data === "" || data === null) {
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

        $scope.toggle_field = function(field) {
            $scope.current_service[field] = !$scope.current_service[field]
        };

        $scope.enable_field = function(field) {
            if ($scope.current_service !== null && $scope.current_service !== undefined && field in $scope.current_service){
                $scope.current_service[field] = true
            }
            else if ($scope.current_docker_config !== null && $scope.current_docker_config !== undefined && field in $scope.current_docker_config){
                $scope.current_docker_config[field] = true
            }
            else if ($scope.current_service.update_config !== null && $scope.current_service.update_config !== undefined){
                $scope.current_service.update_config[field] = true
            }
        };

        $scope.disable_field = function(field) {
            if ($scope.current_service !== null && $scope.current_service !== undefined && field in $scope.current_service){
                $scope.current_service[field] = false
            }
            else if ($scope.current_docker_config !== null && $scope.current_docker_config !== undefined && field in $scope.current_docker_config){
                $scope.current_docker_config[field] = false
            }
            else if ($scope.current_service.update_config !== null && $scope.current_service.update_config !== undefined){
                $scope.current_service.update_config[field] = false
            }
        };

        $scope.add_dependency = function () {
            $scope.editmode = false;
            $("#docker_image").removeClass('has-error');
            $scope.comp_temp_error = null;
            $("#docker_name").removeClass('has-error');
            $scope.current_docker_config_name = null;
            $scope.current_docker_config_name_old= null;
            $scope.current_docker_volumes = {};
            $scope.conf_temp = {
                key: "",
                val: ""
            };
            $("#new_vol_name").removeClass('has-error');
            $("#new_vol").removeClass('has-error');
            $scope.vol_name_temp = "";
            $scope.vol_temp = {
                mount_path: "",
                capacity: "",
                storage_class: "",
            };

            $scope.current_docker_config = {
                allow_internet_access: false,
                command: [],
                cpu_cores: 1.0,
                environment: [],
                image: "",
                ram_mb: 512,
                ram_mb_min: 128
            };
            $scope.docker_type = 'dependency';
            $("#dockerModal").modal('show');
        };

        $scope.remove_dependency = function (dep) {
            delete $scope.current_service.dependencies[dep];
        };

        $scope.edit_docker_config = function (type, docker_config, name, volumes) {
            $scope.editmode = true;
            $("#docker_image").removeClass('has-error');
            $scope.comp_temp_error = null;
            $scope.conf_temp = {
                key: "",
                val: ""
            };
            $scope.vol_name_temp = "";
            $scope.vol_temp = {
                mount_path: "",
                capacity: "",
                storage_class: "",
            };

            $scope.backup_docker = docker_config;
            $scope.current_docker_config = JSON.parse(JSON.stringify(docker_config));
            $scope.docker_type = type;
            $("#docker_name").removeClass('has-error');
            $scope.current_docker_config_name = name;
            $scope.current_docker_config_name_old = name;
            $scope.current_docker_volumes = volumes
            $("#dockerModal").modal('show');
        };

        $scope.add_volume = function (){
            $("#new_vol_name").removeClass('has-error');
            $("#new_vol").removeClass('has-error');
            if ($scope.vol_name_temp === "" || $scope.vol_name_temp === null || $scope.vol_name_temp === undefined ){
                $("#new_vol_name").addClass('has-error');
                return
            }
            if ($scope.vol_temp.mount_path === "" || $scope.vol_temp.mount_path === null || $scope.vol_temp.mount_path === undefined ){
                $("#new_vol").addClass('has-error');
                return
            }
            if ($scope.vol_temp.capacity === "" || $scope.vol_temp.capacity === null || $scope.vol_temp.capacity === undefined ){
                $("#new_vol").addClass('has-error');
                return
            }
            if ($scope.vol_temp.storage_class === "" || $scope.vol_temp.storage_class === null || $scope.vol_temp.storage_class === undefined ){
                $("#new_vol").addClass('has-error');
                return
            }
            $scope.current_docker_volumes[$scope.vol_name_temp] = $scope.vol_temp;

            $scope.vol_name_temp = "";
            $scope.vol_temp = {
                mount_path: "",
                capacity: "",
                storage_class: "",
            };
        };

        $scope.remove_volume = function (vol_name){
            delete $scope.current_docker_volumes[vol_name]
        };

        $scope.save_docker_config = function(){
            if ($scope.current_docker_config.image === "" || $scope.current_docker_config.image === null || $scope.current_docker_config.image === undefined){
                $("#docker_image").addClass('has-error');
                return;
            }
            if ($scope.docker_type === "dependency" && ($scope.current_docker_config_name === "" || $scope.current_docker_config_name === null || $scope.current_docker_config_name === undefined)){
                $("#docker_name").addClass('has-error');
                return;
            }
            if ($scope.docker_type === "service_container"){
                $scope.current_service.docker_config = $scope.current_docker_config;
            }
            else if ($scope.docker_type === "update_container"){
                $scope.current_service.update_config.run_options = $scope.current_docker_config;
            }
            else if ($scope.docker_type === "dependency"){
                delete $scope.current_service.dependencies[$scope.current_docker_config_name_old];
                $scope.current_service.dependencies[$scope.current_docker_config_name] = {
                    container: $scope.current_docker_config,
                    volumes: $scope.current_docker_volumes
                };
            }

            $("#dockerModal").modal('hide');
        };

        $scope.add_source_config = function () {
            $scope.editmode = false;
            $("#source_uri").removeClass('has-error');
            $("#source_resulting_filename").removeClass('has-error');
            $scope.source_name_error = '';
            $scope.comp_temp_error = null;
            $scope.conf_temp = {
                key: "",
                val: ""
            };

            $scope.current_source = {};
            $("#sourceModal").modal('show');
        };

        $scope.edit_source_config = function (source) {
            $scope.editmode = true;
            $("#source_uri").removeClass('has-error');
            $("#source_resulting_filename").removeClass('has-error');
            $scope.source_name_error = '';
            $scope.comp_temp_error = null;
            $scope.conf_temp = {
                key: "",
                val: ""
            };

            $scope.backup_source = source;
            $scope.current_source = JSON.parse(JSON.stringify(source));
            $("#sourceModal").modal('show');
        };

        $scope.save_source_config = function(){
            if ($scope.current_source.uri === "" || $scope.current_source.uri === null || $scope.current_source.uri === undefined){
                $("#source_uri").addClass('has-error');
                return;
            }

            if ($scope.current_source.name === "" || $scope.current_source.name === null || $scope.current_source.name === undefined){
                $("#source_resulting_filename").addClass('has-error');
                return;
            }

            if($scope.editmode){
                for (let i in $scope.current_service.update_config.sources){
                    if ($scope.current_source.name === $scope.current_service.update_config.sources[i].name){
                        $scope.current_service.update_config.sources.splice(i, 1, $scope.current_source);
                        break;
                    }
                }
            }
            else {
                for (let i in $scope.current_service.update_config.sources){
                    if ($scope.current_source.name === $scope.current_service.update_config.sources[i].name){
                        $("#source_resulting_filename").addClass('has-error');
                        $scope.source_name_error = "This name already exists, it should be unique";
                        return;
                    }
                }
                $scope.current_service.update_config.sources.push($scope.current_source)

            }
            $scope.current_source = null;
            $("#sourceModal").modal('hide');
        };

        $scope.delete_source_config = function(source){
            let idx = $scope.current_service.update_config.sources.indexOf(source);
            if (idx !== -1){
                $scope.current_service.update_config.sources.splice(idx, 1);
            }
        };

        $scope.remove_environment = function (key, val) {
            for (let i in $scope.current_docker_config.environment){
                if ($scope.current_docker_config.environment[i].name === key && $scope.current_docker_config.environment[i].value === val){
                    $scope.current_docker_config.environment.splice(i, 1);
                    return;
                }
            }
        };

        $scope.add_environment = function () {
            $("#new_conf_temp_key").removeClass("has-error");
            $("#new_conf_temp_val").removeClass("has-error");
            $scope.conf_temp_error = null;

            if (!("environment" in $scope.current_docker_config)){
                $scope.current_docker_config.environment = [];
            }

            if ($scope.conf_temp.key === "" || $scope.conf_temp.key == null) {
                $scope.conf_temp_error = "Environment variable name is required.";
                $("#new_conf_temp_key").addClass("has-error");
                $("#new_conf_temp_val").removeClass("has-error");
                return;
            }

            if ($scope.conf_temp.val === "" || $scope.conf_temp.val == null) {
                $scope.conf_temp_error = "Each environment variable requires a value.";
                $("#new_conf_temp_key").removeClass("has-error");
                $("#new_conf_temp_val").addClass("has-error");
                return;
            }
            $scope.current_docker_config.environment.push({
                name: $scope.conf_temp.key,
                value: $scope.conf_temp.val
            });

            $scope.conf_temp = {
                key: "",
                val: ""
            };
        };

        $scope.remove_header = function (key, val) {
            for (let i in $scope.current_source.headers){
                if ($scope.current_source.headers[i].name === key && $scope.current_source.headers[i].value === val){
                    $scope.current_source.headers.splice(i, 1);
                    return;
                }
            }
        };

        $scope.add_header = function () {
            $("#new_conf_temp_key").removeClass("has-error");
            $("#new_conf_temp_val").removeClass("has-error");
            $scope.conf_temp_error = null;

            if (!("headers" in $scope.current_source)){
                $scope.current_source.headers = [];
            }

            if ($scope.conf_temp.key === "" || $scope.conf_temp.key == null) {
                $scope.conf_temp_error = "Header name is required.";
                $("#new_conf_temp_key").addClass("has-error");
                $("#new_conf_temp_val").removeClass("has-error");
                return;
            }

            if ($scope.conf_temp.val === "" || $scope.conf_temp.val == null) {
                $scope.conf_temp_error = "Each header requires a value.";
                $("#new_conf_temp_key").removeClass("has-error");
                $("#new_conf_temp_val").addClass("has-error");
                return;
            }
            $scope.current_source.headers.push({
                name: $scope.conf_temp.key,
                value: $scope.conf_temp.val
            });

            $scope.conf_temp = {
                key: "",
                val: ""
            };
        };

        $scope.del = function () {
            swal({
                    title: "Delete Service?",
                    text: "You are about to delete the current service. Are you sure?",
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
                url: "/api/v4/service/" + $scope.current_service.name + "/"
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Service " + $scope.current_service.name + " successfully deleted!";
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

                    if (data === "" || data === null) {
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

        $scope.editService = function (service) {
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.saved = '';

            // Reset variables
            $scope.spec_temp = {
                type: "bool",
                list: [],
                default: false,
                name: ""
            };
            $scope.spec_error = "";

            $scope.conf_temp.type = "str";
            $scope.conf_temp.key = "";
            $scope.conf_temp.val = "";

            $("#spec_default").val("false");
            $("#conf_temp_val").val("");

            $http({
                method: 'GET',
                url: "/api/v4/service/versions/" + service.name + "/"
            })
                .success(function (data) {
                    $scope.current_service_versions = data.api_response;
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

            $http({
                method: 'GET',
                url: "/api/v4/service/" + service.name + "/"
            })
                .success(function (data) {
                    $scope.loading_extra = false;
                    $scope.current_service = data.api_response;
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

                    if (data.api_error_message) {
                        $scope.error = data.api_error_message;
                    }
                    else {
                        $scope.error = config.url + " (" + status + ")";
                    }
                    scroll(0, 0);
                });
        };

        //Save params
        $scope.save = function () {
            $scope.loading_extra = true;
            $scope.error = '';
            $scope.success = '';

            for (let idx in $scope.current_service.submission_params) {
                $scope.current_service.submission_params[idx].value = $scope.current_service.submission_params[idx].default;
            }

            $http({
                method: 'POST',
                url: "/api/v4/service/" + $scope.current_service.name + "/",
                data: $scope.current_service
            })
                .success(function () {
                    $scope.loading_extra = false;
                    $("#myModal").modal('hide');
                    $scope.success = "Service " + $scope.current_service.name + " successfully updated!";
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

                    if (data === "" || data === null) {
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

        //Load params from datastore
        $scope.start = function () {
            $scope.load_data();
        };

        //Load params from datastore
        $scope.update = function (name, update_data) {
            $scope.loading_extra = true;

            $http({
                method: 'PUT',
                url: "/api/v4/service/update/",
                data: {name: name, update_data: update_data}
            })
            .success(function (data) {
                $scope.loading_extra = false;
                if (data.api_response.status === 'updating'){
                    $scope.update_data[name]['updating'] = true;
                }
                else {
                    $scope.update_data[name]['updating'] = true;
                    $timeout(function () {
                        $scope.load_data();
                    }, 2000);
                }
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;
                $scope.updating[name] = false;

                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "" || data === null || status === 400) {
                    $scope.service_list = [];
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

        //Pager methods
        $scope.load_data = function () {
            $scope.loading_extra = true;

            $http({
                method: 'GET',
                url: "/api/v4/service/all/"
            })
            .success(function (data) {
                $scope.loading_extra = false;
                $scope.service_list = data.api_response;
                $scope.started = true;
            })
            .error(function (data, status, headers, config) {
                $scope.loading_extra = false;

                if (status === 401){
                    window.location = "/login.html?next=" + encodeURIComponent(window.location.pathname + window.location.search);
                    return;
                }

                if (data === "" || data === null || status === 400) {
                    $scope.service_list = [];
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

            $http({
                method: 'GET',
                url: "/api/v4/service/updates/"
            })
            .success(function (data) {
                $scope.update_data = data.api_response;
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
                scroll(0, 0);
            });

            $http({
                method: 'GET',
                url: "/api/v4/service/constants/"
            })
            .success(function (data) {
                $scope.service_constants = data.api_response;
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
                scroll(0, 0);
            });
        };

        //Service Specific functions/vars
        $scope.spec_temp = {
            type: "bool",
            list: [],
            default: false,
            name: ""
        };
        $scope.spec_error = "";

        $scope.remove_specific = function (name) {
            for (let idx in $scope.current_service.submission_params) {
                if ($scope.current_service.submission_params[idx].name === name) {
                    $scope.current_service.submission_params.splice(idx, 1);
                    break;
                }
            }

        };

        $scope.add_specific = function () {
            for (let idx in $scope.current_service.submission_params) {
                if ($scope.current_service.submission_params[idx].name === $scope.spec_temp.name) {
                    $scope.spec_error = "This user specified parameter name already exists.";
                    $("#new_spec_name").addClass("has-error");
                    return;
                }
            }
            if ($scope.spec_temp.name === "" || $scope.spec_temp.name == null) {
                $scope.spec_error = "Name field is required.";
                $("#new_spec_name").addClass("has-error");
                return;
            }

            let temp = {
                'name': $scope.spec_temp.name,
                'type': $scope.spec_temp.type,
                'default': $scope.spec_temp.default,
                'value': $scope.spec_temp.default
            };
            if ($scope.spec_temp.type === 'list') {
                temp['list'] = $scope.spec_temp.list;
            }

            $scope.current_service.submission_params.push(temp);

            $scope.spec_temp = {
                type: "bool",
                list: [],
                default: false,
                name: ""
            };

            $scope.spec_error = "";
        };

        $scope.$watch('spec_error', function () {
            if ($scope.spec_error === "") {
                $("#new_spec_name").removeClass("has-error");
                $("#new_spec_type").removeClass("has-error");
                $("#new_spec_default").removeClass("has-error");
            }

        });

        $scope.$watch('spec_temp.type', function () {
            if ($scope.spec_temp.type === "bool") {
                $scope.spec_temp.default = false;
                $("#spec_default").val("false");
            }
            else if ($scope.spec_temp.type === "list") {
                $scope.spec_temp.list = [];
                $scope.spec_temp.default = "";
                $("#spec_default").val("");
            }
            else if ($scope.spec_temp.type === "int") {
                $scope.spec_temp.default = 1;
                $("#spec_default").val("1");
            }
            else {
                $scope.spec_temp.default = "";
                $("#spec_default").val("");
            }
        });

        //Evironment Variables functions/vars
        $scope.conf_temp = {
            type: "str",
            key: "",
            val: ""
        };

        $scope.remove_meta = function (key) {
            delete $scope.current_service.config[key];
        };

        $scope.add_meta = function () {
            if ($scope.conf_temp.key in $scope.current_service.config) {
                $scope.conf_temp_error = "This environement variable name already exists.";
                $("#new_conf_temp_key").addClass("has-error");
                return
            }

            if ($scope.conf_temp.key === "" || $scope.conf_temp.key == null) {
                $scope.conf_temp_error = "Environment variable name is required.";
                $("#new_conf_temp_key").addClass("has-error");
                return;
            }
            $scope.current_service.config[$scope.conf_temp.key] = $scope.conf_temp.val;

            $scope.conf_temp = {
                type: "str",
                key: "",
                val: ""
            };
        };

        $scope.$watch('conf_temp_error', function () {
            if ($scope.conf_temp_error === "") {
                $("#new_conf_temp_key").removeClass("has-error");
                $("#new_conf_temp_type").removeClass("has-error");
                $("#new_conf_temp_val").removeClass("has-error");
            }

        });

        $scope.$watch('conf_temp.type', function () {
            if ($scope.conf_temp.type === "bool") {
                $scope.conf_temp.val = false;
                $("#conf_temp_val").val("false");
            }
            else if ($scope.conf_temp.type === "list") {
                $scope.conf_temp.val = [];
                $("#conf_temp_val").val("");
            }
            else if ($scope.conf_temp.type === "int") {
                $scope.conf_temp.val = 1;
                $("#conf_temp_val").val("1");
            }
            else if ($scope.conf_temp.type === "json") {
                $scope.conf_temp.val = {};
                $("#conf_temp_val").val("1");
            }
            else {
                $scope.conf_temp.val = "";
                $("#conf_temp_val").val("");
            }
        });
    });
