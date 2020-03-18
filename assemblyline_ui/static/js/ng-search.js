let ngSearch = angular.module('search', []);

ngSearch.controller('SearchController', function ($scope, $timeout, $http) {
    $scope.suggestions = {'all': ["OR", "AND", "NOT", "TO", "now", "d", "M", "y", "h", "m"]};
    $scope.favorites = {};
    $scope.favorites_toggled = [];
    $scope.global_filters = {};
    $scope.global_toggled = [];
    $scope.query = "";
    $scope.bucket = null;
    $scope.should_load_suggestion = true;
    $scope.page = null;
    $scope.disabled = false;
    $scope.cur_favorite = {};
    $scope.labels = [];
    $scope.last_error = "";
    $scope.load_favorites = false;
    $scope.load_global_favorites = false;

    $scope.isOwner = function (created_by) {
        return created_by === $scope.user.uname;

    };

    $scope.toggleFQ = function (filter_idx, isPersonal) {
        let filter_list = null;

        if (isPersonal) {
            filter_list = $scope.favorites;
        }
        else {
            filter_list = $scope.global_filters;
        }

        let filter_query = filter_list[filter_idx].query;
        let idx = $scope.$parent.filter_queries.indexOf(filter_query);
        if (idx === -1) {
            $scope.$parent.filter_queries.push(filter_query)
        }
        else {
            $scope.$parent.filter_queries.splice(idx, 1)
        }

        $scope.$parent.gen_forced_filter(false);
    };


    $scope.getKeys = function (o) {
        try {
            return Object.keys(o);
        } catch (ex) {
            return [];
        }
    };

    $scope.inFavorites = function (query) {
        for (let id in $scope.favorites) {
            let temp_fav = $scope.favorites[id];
            if (temp_fav.query === query) {
                return true;
            }
        }
        return false;
    };

    $scope.nameOfQuery = function (query) {
        for (let id in $scope.favorites) {
            let temp_fav = $scope.favorites[id];
            if (temp_fav.query === query) {
                return temp_fav.name;
            }
        }
        return "";
    };

    $scope.idOfName = function (name, type) {
        let filter_list;
        if (type === "global") {
            filter_list = $scope.global_filters;
        }
        else {
            filter_list = $scope.favorites;
        }

        for (let id in filter_list) {
            let temp_fav = filter_list[id];
            if (temp_fav.name === name) {
                return id;
            }
        }
        return null;
    };

    $scope.receiveClassification = function (classification) {
        $scope.cur_favorite.classification = classification;
    };

    $scope.getToday = function () {
        let today = new Date();
        let dd = today.getDate();
        if (dd < 10) {
            dd = '0' + dd;
        }
        else {
            dd = '' + dd;
        }
        let mm = today.getMonth() + 1;
        if (mm < 10) {
            mm = '0' + mm;
        }
        else {
            mm = '' + mm;
        }

        return today.getFullYear() + mm + dd;
    };

    $scope.promptAddFavorites = function (query, default_classification) {
        if ($scope.page == null) return;
        if (default_classification === undefined) default_classification = null;

        $scope.cur_favorite = {
            classification: default_classification,
            created_by: null,
            name: null,
            query: query,
            type: 'private'
        };
        $scope.edit_mode = false;
        $scope.last_error = "";
        $("#confirmModal").modal('show');
    };

    $scope.editFavorites = function (fav, type) {
        if ($scope.page == null) return;
        $scope.cur_favorite = fav;
        $scope.cur_favorite.type = type;
        $scope.edit_mode = true;
        $scope.last_error = "";
        $("#confirmModal").modal('show');
    };

    $scope.addToFavorites = function () {
        if ($scope.page == null) return;
        if ($scope.cur_favorite.name === '' || $scope.cur_favorite.name == null || $scope.cur_favorite.name === undefined) {
            $scope.last_error = "Your filter needs a name";
            return;
        }

        let user = $scope.user.uname;
        let data = $scope.cur_favorite;
        let global = $scope.cur_favorite.type === 'global';

        if (!$scope.edit_mode && $scope.idOfName($scope.cur_favorite.name, $scope.cur_favorite.type) != null) {
            $scope.last_error = "This filter name already exists";
            return;
        }

        if (global) {
            data.created_by = user;
            user = "__global__";
        }

        if ($scope.cur_favorite.label) {
            for (let i in $scope.cur_favorite.label) {
                $scope.cur_favorite.label[i] = $scope.cur_favorite.label[i].toUpperCase();
            }
        }

        for (let idx in $scope.cur_favorite) {
            if ($scope.cur_favorite[idx] == null || $scope.cur_favorite[idx] === '') {
                delete $scope.cur_favorite[idx];
            }
        }

        if ($scope.edit_mode) {
            $scope.do_remove($scope.cur_favorite.name, $scope.cur_favorite.type)
        }

        delete $scope.cur_favorite.type;

        $http({
            method: 'PUT',
            url: "/api/v4/user/favorites/" + user + "/" + $scope.page + "/",
            data: data
        })
            .error(function (data, status, headers, config) {
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
        if (global) {
            $scope.global_filters.push(data);
        }
        else {
            $scope.favorites.push(data);
        }
        $("#confirmModal").modal('hide');
    };

    $scope.do_remove = function (name, type) {
        let user = $scope.user.uname;
        if (type === 'global') {
            user = '__global__';
        }
        $http({
            method: 'DELETE',
            url: "/api/v4/user/favorites/" + user + "/" + $scope.page + "/",
            data: name
        })
            .error(function (data, status, headers, config) {
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
        let del_idx = null;
        if (type === 'global') {
            del_idx = $scope.idOfName(name, type);
            if (del_idx != null) $scope.global_filters.splice(del_idx, 1);
        }
        else {
            del_idx = $scope.idOfName(name, type);
            if (del_idx != null) $scope.favorites.splice(del_idx, 1);
        }
    };

    $scope.removeFromFavorites = function (name, type) {
        if ($scope.page == null) return;
        swal({
                title: "Delete favorite",
                text: "\n\nAre you sure you want to delete this favorite?\n\n" + name + "\n\n",
                type: "info",
                showCancelButton: true,
                confirmButtonColor: "#d9534f",
                confirmButtonText: "Yes, do it!",
                closeOnConfirm: true
            },
            function () {
                $scope.do_remove(name, type);
            });
    };

    $scope.load_suggestions = function () {
        if ($scope.disabled) return;
        let bucket = "ALL";

        if ($scope.bucket != null) {
            bucket = $scope.bucket;
        }
        $http({
            method: 'GET',
            url: "/api/v4/search/fields/" + bucket + "/"
        })
            .success(function (data) {
                if (bucket === "ALL") {
                    for (let bucket_name in data.api_response) {
                        $scope.suggestions[bucket_name] = ["OR", "AND", "NOT", "TO", "now", "d", "M", "y", "h", "m"];
                        let res_bucket = data.api_response[bucket_name];
                        for (let field_name in res_bucket) {
                            let field = res_bucket[field_name];
                            let lookup_name = field_name + ":";
                            if (field.indexed && $scope.suggestions[bucket_name].indexOf(lookup_name) === -1) {
                                $scope.suggestions[bucket_name].push(lookup_name);
                            }
                        }
                    }
                }
                else{
                    $scope.suggestions[bucket] = ["OR", "AND", "NOT", "TO", "now", "d", "M", "y", "h", "m"];
                    for (let n_field in data.api_response) {
                         let f = data.api_response[n_field];
                         let l_name = n_field + ":";
                         if (f.indexed && $scope.suggestions[bucket].indexOf(l_name) === -1) {
                             $scope.suggestions[bucket].push(l_name);
                         }
                    }
                }
            })
            .error(function (data, status, headers, config) {
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

        if ($scope.page == null) {
            return;
        }

        if ($scope.load_favorites) {
            $http({
                method: 'GET',
                url: "/api/v4/user/favorites/" + $scope.user.uname + "/"
            })
                .success(function (data) {
                    if (data.api_response == null) {
                        $scope.favorites = {};
                        $scope.favorites_toggled = []
                    }
                    else {
                        $scope.favorites = data.api_response[$scope.page];
                        if ($scope.$parent.filter_queries !== undefined) {
                            let idx = 0;
                            for (let fav_idx in $scope.favorites) {
                                $scope.favorites_toggled[idx] = $scope.$parent.filter_queries.indexOf($scope.favorites[fav_idx].query) !== -1;
                                idx++;
                            }
                        }
                    }
                })
                .error(function (data, status, headers, config) {
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
        }
        if ($scope.load_global_favorites) {
            $http({
                method: 'GET',
                url: "/api/v4/user/favorites/__global__/"
            })
                .success(function (data) {
                    if (data.api_response == null) {
                        $scope.global_filters = {};
                        $scope.global_toggled = []
                    }
                    else {
                        $scope.global_filters = data.api_response[$scope.page];
                        if ($scope.$parent.filter_queries !== undefined) {
                            let idx = 0;
                            for (let fav_idx in $scope.global_filters) {
                                $scope.global_toggled[idx] = $scope.$parent.filter_queries.indexOf($scope.global_filters[fav_idx].query) !== -1;
                                idx++;
                            }
                        }
                    }
                })
                .error(function (data, status, headers, config) {
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
        }
    };

    $timeout(function () {
        if ($scope.should_load_suggestion) {
            $scope.load_suggestions();
        }
    }, 0);
});

ngSearch.controller('SearchControllerQuick', function ($scope, $http) {
    $scope.quick_suggestions = ["OR", "AND", "NOT", "TO", "now", "d", "M", "y", "h", "m"];
    $scope.quick = "";

    /*$http({
        method: 'GET',
        url: "/api/v4/search/fields/ALL/"
    })
        .success(function (data) {
            for (let bucket_name in data.api_response) {
                let bucket = data.api_response[bucket_name];
                for (let field_name in bucket) {
                    let field = bucket[field_name];
                    let lookup_name = field_name + ":";
                    if (field.indexed && $scope.quick_suggestions.indexOf(lookup_name) === -1) {
                        $scope.quick_suggestions.push(lookup_name);
                    }
                }
            }
        })
        .error(function (data, status, headers, config) {
        });*/
});