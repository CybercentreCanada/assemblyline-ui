/* global angular */
'use strict';

/**
 * Main App Module
 */
let app = angular.module('app', ['search', 'utils', 'ui.bootstrap'])
    .controller('ALController', function ($scope, $timeout) {
        $scope.user = null;

        //DEBUG MODE
        $scope.debug = false;
        $scope.showParams = function () {
            console.log("Scope", $scope)
        };

        //Error handling
        $scope.error = '';
        $scope.success = '';

        //Do nothing
        $scope.start = function () {
            if (Object.keys(classification_definition).length === 0) {
                $timeout($scope.start, 50);
            }
            else {
                $scope.classification_definition = classification_definition;
            }
        };

        $scope.level_list = function () {
            let out = [];
            if ($scope.classification_definition !== null && $scope.classification_definition !== undefined){
                for (let i in $scope.classification_definition.levels_map) {
                    if (!isNaN(parseInt(i))) {
                        out.push($scope.classification_definition.levels_map[i]);
                    }
                }
            }
            return out;
        };

        $scope.getLength = function (obj) {
            if (obj === undefined || obj === null){
                return 0;
            }
            return Object.keys(obj).length;
        }
    });

