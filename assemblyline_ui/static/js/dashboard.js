/* global angular */
'use strict';

/**
 * Main App Module
 */
function add(a, b) {
    return a + b;
}

//noinspection JSUnusedLocalSymbols
let app = angular.module('app', ['utils', 'search', 'socket-io', 'ngAnimate', 'ui.bootstrap'])
    .factory('mySocket', function (socketFactory) {
        let mySocket = socketFactory({namespace: '/status'});
        mySocket.forward('DispatcherHeartbeat');
        mySocket.forward('AlerterHeartbeat');
        mySocket.forward('ExpiryHeartbeat');
        mySocket.forward('ArchiveHeartbeat');
        mySocket.forward('ScalerHeartbeat');
        mySocket.forward('ScalerStatusHeartbeat');
        mySocket.forward('IngestHeartbeat');
        mySocket.forward('ServiceHeartbeat');
        mySocket.forward('monitoring');
        mySocket.setConnectionCallback(function () {
            mySocket.emit("monitor", {'status': "start"});
        });
        return mySocket;
    })
    .controller('ALController', function ($scope, $timeout, mySocket) {
        $scope.user = null;
        $scope.socket_status = 'init';
        $scope.data = {
            alerter: {
                instances: 0,
                queues: {
                    alert: 0
                },
                metrics: {
                    created: 0,
                    error: 0,
                    received: 0,
                    updated: 0
                }
            },
            dispatcher: {
                instances: 0,
                inflight:{
                    outstanding: 0,
                    max: 0
                },
                queues: {
                    ingest: 0
                },
                metrics: {
                    files_completed: 0,
                    submissions_completed: 0
                }
            },
            expiry: {
                instances: 0,
                queues: {
                    alert: 0,
                    cached_file: 0,
                    emptyresult: 0,
                    error: 0,
                    file: 0,
                    filescore: 0,
                    result: 0,
                    submission: 0,
                    submission_tree: 0,
                    submission_summary: 0,
                },
                metrics: {
                    alert: 0,
                    cached_file: 0,
                    emptyresult: 0,
                    error: 0,
                    file: 0,
                    filescore: 0,
                    result: 0,
                    submission: 0,
                    submission_tree: 0,
                    submission_summary: 0,
                },
                archive: {
                    alert: 0,
                    cached_file: 0,
                    emptyresult: 0,
                    error: 0,
                    file: 0,
                    filescore: 0,
                    result: 0,
                    submission: 0,
                    submission_tree: 0,
                    submission_summary: 0,
                }
            },
            ingester: {
                instances: 0,
                metrics:{
                    cache_miss: 0,
                    cache_expired: 0,
                    cache_stale: 0,
                    cache_hit_local: 0,
                    cache_hit: 0,
                    bytes_completed: 0,
                    bytes_ingested: 0,
                    duplicates: 0,
                    error: 0,
                    files_completed: 0,
                    skipped: 0,
                    submissions_completed: 0,
                    submissions_ingested: 0,
                    timed_out: 0,
                    whitelisted: 0,
                },
                processing: {
                    inflight: 0
                },
                processing_chance: {
                    critical: 1,
                    high: 1,
                    medium: 1,
                    low: 1
                },
                queues: {
                    ingest: 0,
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0
                }
            },
            scaler: {
                memory_total: 0,
                memory_free: 0,
                cpu_total: 0,
                cpu_free: 0
            },
            services: {
                up: [],
                down: [],
                metrics: {}
            }
        };

        $scope.service_defaults = {
            duty_cycle: 0,
            instances: 0,
            last_hb: Math.floor(new Date().getTime() / 1000),
            metrics: {
                cache_hit: 0,
                cache_miss: 0,
                cache_skipped: 0,
                execute: 0,
                fail_recoverable: 0,
                fail_nonrecoverable: 0,
                scored: 0,
                not_scored: 0
            },
            scaler: {
                running: 0,
                target: 0,
                minimum: 0,
                maximum: 0,
                dynamic_maximum: 0,
                queue: 0,
                pressure: 0.0,
                duty_cycle: 0.0
            },
            queue: 0,
            activity: {
                busy: 0,
                idle: 0
            },
            service_name: null
        };

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        $scope.$on('socket:IngestHeartbeat', function (event, data) {
            try {
                console.log('Socket-IO::IngestHeartbeat message', data);
                $scope.data.ingester = data;
            }
            catch (e) {
                console.log('Socket-IO::IngestHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.ingester_in_error = function (ingester) {
            try {
                if (ingester.processing_chance.critical !== 1) {
                    return true;
                }
                if (ingester.processing_chance.high !== 1) {
                    return true;
                }
                if (ingester.processing_chance.medium !== 1) {
                    return true;
                }
                if (ingester.processing_chance.low !== 1) {
                    return true;
                }
                if (ingester.metrics.bytes_completed === 0 && ingester.metrics.bytes_ingested !== 0) {
                    return true;
                }
                if (ingester.ingest > 100000) {
                    return true;
                }
            } catch (e) {
                return true;
            }
            return false;
        };

        $scope.round = function (val) {
            return Math.round(val);
        };

        $scope.$on('socket:DispatcherHeartbeat', function (event, data) {
            try {
                console.log('Socket-IO::DispatcherHeartbeat message', data);
                $scope.data.dispatcher = data;
            }
            catch (e) {
                console.log('Socket-IO::DispatcherHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.dispatcher_in_error = function (dispatcher) {
            return !!(dispatcher.queues.ingest >= dispatcher.queues.max_inflight);

        };

        $scope.$on('socket:AlerterHeartbeat', function (event, data) {
            try {
                console.log('Socket-IO::AlerterHeartbeat message', data);
                $scope.data.alerter = data;
            }
            catch (e) {
                console.log('Socket-IO::AlerterHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.alerter_in_error = function (alerter) {
            return !!(alerter.metrics.error > 0);

        };

        $scope.$on('socket:ExpiryHeartbeat', function (event, data) {
            try {
                console.log('Socket-IO::ExpiryHeartbeat message', data);
                let old_archive = $scope.data.expiry.archive;
                $scope.data.expiry = data;
                $scope.data.expiry.archive = old_archive;
            }
            catch (e) {
                console.log('Socket-IO::ExpiryHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.$on('socket:ArchiveHeartbeat', function (event, data) {
            try {
                console.log('Socket-IO::ArchiveHeartbeat message', data);
                $scope.data.expiry.archive = data.metrics;
            }
            catch (e) {
                console.log('Socket-IO::ArchiveHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.$on('socket:ScalerHeartbeat', function (event, data) {
            try {
                console.log('Socket-IO::ScalerHeartbeat message', data);
                $scope.data.scaler = data.metrics;

                $scope.cpu_gauge.moveTo(Math.min(1-($scope.data.scaler.cpu_free/$scope.data.scaler.cpu_total), 1));
                $scope.ram_gauge.moveTo(Math.min(1-($scope.data.scaler.memory_free/$scope.data.scaler.memory_total), 1));
            }
            catch (e) {
                console.log('Socket-IO::ScalerHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.$on('socket:ScalerStatusHeartbeat', function (event, data) {
            try {
                console.log('Socket-IO::ScalerStatusHeartbeat message', data);
                if (!$scope.data.services.metrics.hasOwnProperty(data.service_name)){
                    $scope.data.services.metrics[data.service_name] = JSON.parse(JSON.stringify($scope.service_defaults));
                }
                $scope.data.services.metrics[data.service_name].service_name = data.service_name;
                $scope.data.services.metrics[data.service_name].scaler = data.metrics;
            }
            catch (e) {
                console.log('Socket-IO::ScalerStatusHeartbeat [ERROR] Invalid message', data, e);
            }

        });

        $scope.expiry_in_error = function () {
            // TBD
            return false;

        };

        $scope.$on('socket:ServiceHeartbeat', function (event, data) {
            let cur_time = Math.floor(new Date().getTime() / 1000);
            try {
                console.log('Socket-IO::ServiceHeartbeat message', data);
                if (!$scope.data.services.metrics.hasOwnProperty(data.service_name)){
                    $scope.data.services.metrics[data.service_name] = JSON.parse(JSON.stringify($scope.service_defaults));
                }
                $scope.data.services.metrics[data.service_name].service_name = data.service_name;
                $scope.data.services.metrics[data.service_name].instances = data.instances;
                $scope.data.services.metrics[data.service_name].metrics = data.metrics;
                $scope.data.services.metrics[data.service_name].activity = data.activity;
                $scope.data.services.metrics[data.service_name].queue = data.queue;
                $scope.data.services.metrics[data.service_name].last_hb = cur_time;
            }
            catch (e) {
                console.log('Socket-IO::ServiceHeartbeat [ERROR] Invalid message', data, e);
            }

            $scope.data.services.up = [];
            $scope.data.services.down = [];

            for (let k in $scope.data.services.metrics){
                let srv = $scope.data.services.metrics[k];
                if ((cur_time - srv.last_hb) > 60){
                    $scope.data.services.down.push(k)
                }
                else{
                    $scope.data.services.up.push(k)
                }
            }
        });

        $scope.dump = function (obj) {
            return angular.toJson(obj, true);
        };

        $scope.$on('socket:monitoring', function (event, data) {
            $scope.socket_status = 'ok';
            console.log('Socket-IO::Connected', data);
        });

        $scope.has_errors = function (service) {
            let in_error = false;
            if (service.queue>($scope.data.dispatcher.inflight.max/4)){
                return true;
            }
            else if (service.metrics.fail_nonrecoverable > 0){
                return true;
            }
            return in_error;
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';

        //Startup
        $scope.start = function () {
            console.log("STARTED!");

            $scope.cpu_gauge = create_gauge('cpu');
            $scope.cpu_gauge.render();
            $scope.cpu_gauge.moveTo(0);
            $scope.ram_gauge = create_gauge('ram');
            $scope.ram_gauge.render();
            $scope.ram_gauge.moveTo(0);
        };
    });


