/* global angular */
'use strict';

/**
 * Main App Module
 */
function add(a, b) {
    return a + b;
}

//noinspection JSUnusedLocalSymbols
var app = angular.module('app', ['utils', 'search', 'socket-io', 'ngAnimate', 'ui.bootstrap'])
    .factory('mySocket', function (socketFactory) {
        var mySocket = socketFactory({namespace: '/status'});
        mySocket.forward('DispatcherHeartbeat');
        mySocket.forward('IngestHeartbeat');
        mySocket.forward('ServiceHeartbeat');
        mySocket.forward('monitoring');
        mySocket.setConnectionCallback(function () {
            mySocket.emit("monitor", {'status': "start"});
        });
        return mySocket;
    })
    .controller('ALController', function ($scope, $http, $timeout, mySocket) {
        $scope.user = null;
        $scope.socket_status = 'init';
        $scope.data = {
            dispatcher: {
                count: 0,
                inflight:{
                    outstanding: 0,
                    max: 0
                },
                queues: {
                    ingest: 0,
                    response: 0,
                    control: 0,
                }
            },
            ingester: {
                count: 0,
                counters:{
                    bytes_completed: 0,
                    bytes_ingested: 0,
                    duplicates: 0,
                    files_completed: 0,
                    skipped: 0,
                    submissions_completed: 0,
                    submissions_ingested: 0,
                    timed_out: 0,
                    whitelisted: 0,
                },
                processing: {
                    inflight: 0,
                    waiting: 0,
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
            services: {
                up: [],
                down: [],
                metrics: {}
            }
        };

        $scope.service_defaults = {
            last_hb: Math.floor(new Date().getTime() / 1000),
            queue: 0,
            counters: {
                cached: 0,
                failed: 0,
                processed: 0
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
                if (ingester.counters.bytes_completed === 0) {
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
            if (dispatcher.queues.ingest >= dispatcher.queues.max_inflight && dispatcher.enabled) {
                return true;
            }
            else if (dispatcher.queues.response >= dispatcher.queues.max_inflight && dispatcher.enabled) {
                return true;
            }
            return false;
        };

        $scope.$on('socket:ServiceHeartbeat', function (event, data) {
            var cur_time = Math.floor(new Date().getTime() / 1000);
            try {
                console.log('Socket-IO::ServiceHeartbeat message', data);
                $scope.data.services.metrics[data.service_name] = data;
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
            var in_error = false;
            if (service.queue>($scope.data.dispatcher.inflight.outstanding/2)){
                return true;
            }
            else if (service.counters.failed > 0){
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
        };
    });


