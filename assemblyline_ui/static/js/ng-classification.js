/* global angular */
'use strict';

/*
 * Load classification definition from API into a global letiable.
 */

let classification_definition = {};
$.getJSON("/api/v4/help/classification_definition/", function (data) {
    Object.assign(classification_definition, data.api_response);
});

/***************************************************************************************************
 * Classification static functions
 *  NOTE:   Contrary to the python implementation of the classification engine functions in the
 *          Javascript implementation will not normalize the classification, they are only here
 *          for display purposes.
 */
function get_c12n_level_index(c12n) {
    if (Object.keys(classification_definition).length === 0 || c12n === undefined || c12n == null) return null;
    c12n = c12n.toUpperCase();
    let split_idx = c12n.indexOf("//");
    if (split_idx !== -1) {
        c12n = c12n.slice(0, split_idx)
    }

    if (classification_definition.levels_map[c12n] !== undefined) {
        return classification_definition.levels_map[c12n];
    }
    else if (classification_definition.levels_map_lts[c12n] !== undefined) {
        return classification_definition.levels_map[classification_definition.levels_map_lts[c12n]];
    }
    else if (classification_definition.levels_aliases[c12n] !== undefined) {
        return classification_definition.levels_map[classification_definition.levels_aliases[c12n]];
    }

    return null;
}

function get_c12n_level_text(lvl_idx, long_format) {
    if (long_format === undefined) long_format = true;
    let text = null;
    if (lvl_idx === parseInt(lvl_idx, 10)) {
        lvl_idx = lvl_idx.toString();
    }
    if (classification_definition != null) {
        text = classification_definition.levels_map[lvl_idx];
    }

    if (text === undefined || text == null) {
        text = ""
    }

    if (long_format) {
        return classification_definition.levels_map_stl[text]
    }

    return text
}

function get_c12n_required(c12n, long_format) {
    if (Object.keys(classification_definition).length === 0 || c12n === undefined || c12n == null) return [];
    if (long_format === undefined) long_format = true;
    c12n = c12n.toUpperCase();

    let return_set = [];
    let part_set = c12n.split("/");
    for (let i in part_set) {
        let p = part_set[i];
        if (p in classification_definition.access_req_map_lts) {
            return_set.push(classification_definition.access_req_map_lts[p]);
        }
        else if (p in classification_definition.access_req_map_stl) {
            return_set.push(p);
        }
        else if (p in classification_definition.access_req_aliases) {
            for (let j in classification_definition.access_req_aliases[p]) {
                let a = classification_definition.access_req_aliases[p][j];
                return_set.push(a);
            }
        }
    }

    if (long_format) {
        let out = [];
        for (let k in return_set) {
            let r = return_set[k];
            out.push(classification_definition.access_req_map_stl[r]);
        }

        return out.sort();
    }

    return return_set.sort();
}

function get_c12n_groups(c12n, long_format) {
    if (Object.keys(classification_definition).length === 0 || c12n === undefined || c12n == null) return [];
    if (long_format === undefined) long_format = true;
    c12n = c12n.toUpperCase();

    let g1 = [];
    let g2 = [];

    let parts = c12n.split("//");
    let groups = [];
    for (let p_idx in parts) {
        let grp_part = parts[p_idx].replace("REL TO ", "");
        let temp_group = grp_part.split(",");
        for (let i in temp_group) {
            let t = temp_group[i].trim();
            groups = groups.concat(t.split('/'));
        }
    }

    for (let j in groups) {
        let g = groups[j];
        if (g in classification_definition.groups_map_lts) {
            g1.push(classification_definition.groups_map_lts[g]);
        }
        else if (g in classification_definition.groups_map_stl) {
            g1.push(g);
        }
        else if (g in classification_definition.groups_aliases) {
            for (let k in classification_definition.groups_aliases[g]) {
                let a = classification_definition.groups_aliases[g][k];
                g1.push(a);
            }
        }
        else if (g in classification_definition.subgroups_map_lts) {
            g2.push(classification_definition.subgroups_map_lts[g]);
        }
        else if (g in classification_definition.subgroups_map_stl) {
            g2.push(g);
        }
        else if (g in classification_definition.subgroups_aliases) {
            for (let l in classification_definition.subgroups_aliases[g]) {
                let sa = classification_definition.subgroups_aliases[g][l];
                g2.push(sa);
            }
        }
    }

    if (long_format) {
        let g1_out = [];
        for (let m in g1) {
            let gr = g1[m];
            g1_out.push(classification_definition.groups_map_stl[gr]);
        }

        let g2_out = [];
        for (let n in g2) {
            let sgr = g2[n];
            g2_out.push(classification_definition.subgroups_map_stl[sgr]);
        }

        return {'groups': g1_out.sort(), 'subgroups': g2_out.sort()};
    }

    return {'groups': g1.sort(), 'subgroups': g2.sort()};
}

function get_c12n_parts(c12n, long_format) {
    if (Object.keys(classification_definition).length === 0 || c12n === undefined || c12n == null) return {};
    if (long_format === undefined) long_format = true;
    let out = {
        'lvl_idx': get_c12n_level_index(c12n),
        'req': get_c12n_required(c12n, long_format)
    };

    let grps = get_c12n_groups(c12n, long_format);
    out['groups'] = grps['groups'];
    out['subgroups'] = grps['subgroups'];

    return out;
}

function get_max_c12n(c12n_1, c12n_2, long_format) {
    if (Object.keys(classification_definition).length === 0 || c12n_1 === null || c12n_1 === undefined) return null;
    if (long_format === undefined) long_format = true;
    if (c12n_2 === undefined || c12n_2 === null ) return c12n_1;

    let out = {
        'lvl_idx':  Math.max(get_c12n_level_index(c12n_1), get_c12n_level_index(c12n_2)),
        'req': [...new Set(get_c12n_required(c12n_1, long_format).concat(get_c12n_required(c12n_2, long_format)))]
    };

    let grps_1 = get_c12n_groups(c12n_1, long_format);
    let grps_2 = get_c12n_groups(c12n_2, long_format);
    if (grps_1['groups'].length > 0 && grps_2['groups'].length > 0){
        out['groups'] = grps_1['groups'].filter(value => grps_2['groups'].includes(value))
    }
    else{
        out['groups'] = [...new Set(grps_1['groups'].concat(grps_2['groups']))]
    }
    if (grps_1['subgroups'].length > 0 && grps_2['subgroups'].length > 0){
        out['subgroups'] = grps_1['subgroups'].filter(value => grps_2['subgroups'].includes(value))
    }
    else{
        out['subgroups'] = [...new Set(grps_1['subgroups'].concat(grps_2['subgroups']))]
    }

    return get_c12n_text_from_parts(out, long_format);
}

function get_c12n_text_from_parts(parts, long_format) {
    let lvl_idx = parts['lvl_idx'];
    let req = parts['req'];
    let groups = parts['groups'];
    let subgroups = parts['subgroups'];

    let out = get_c12n_level_text(lvl_idx, long_format);

    let req_grp = [];
    for (let i in req) {
        let r = req[i];
        if (classification_definition.params_map[r] !== undefined) {
            if (classification_definition.params_map[r].is_required_group !== undefined) {
                if (classification_definition.params_map[r].is_required_group) {
                    req_grp.push(r);
                }
            }
        }
    }

    for (let j in req_grp) {
        let rg = req_grp[j];
        req.splice(req.indexOf(rg), 1);
    }

    if (req.length > 0) {
        out += "//" + req.join("/")
    }
    if (req_grp.length > 0) {
        out += "//" + req_grp.join("/")
    }

    if (groups.length > 0) {
        if (req_grp.length > 0) {
            out += "/";
        }
        else {
            out += "//";
        }

        if (groups.length === 1) {
            let group = groups[0];
            if (classification_definition.params_map[group] !== undefined) {
                if (classification_definition.params_map[group].solitary_display_name !== undefined) {
                    out += classification_definition.params_map[group].solitary_display_name
                }
                else {
                    out += "REL TO " + group;
                }
            }
            else {
                out += "REL TO " + group;
            }

        }
        else {
            if (!long_format) {
                for (let alias in classification_definition.groups_aliases) {
                    let values = classification_definition.groups_aliases[alias];
                    if (values.length > 1) {
                        if (JSON.stringify(values.sort()) === JSON.stringify(groups)) {
                            groups = [alias];
                        }
                    }
                }
            }
            out += "REL TO " + groups.join(", ")
        }
    }

    if (subgroups.length > 0) {
        if (groups.length > 0 || req_grp.length > 0) {
            out += "/";
        }
        else {
            out += "//";
        }
        out += subgroups.join("/")
    }


    return out;
}

function get_c12n_text(c12n, long_format) {
    if (Object.keys(classification_definition).length === 0 || c12n === undefined || c12n == null) return c12n;
    if (long_format === undefined) long_format = true;
    let parts = get_c12n_parts(c12n, long_format);
    return get_c12n_text_from_parts(parts, long_format);
}

/***************************************************************************************************
 * ng-utils EXTRA Controllers
 */
utils.controller('classificationCtrl', function ($scope) {
    $scope.classification_definition = classification_definition;
    $scope.active_list = {};
    $scope.disabled_list = {};

    $scope.level_list = function () {
        if (Object.keys(classification_definition).length === 0) return [];
        let out = [];
        for (let i in classification_definition.levels_map) {
            if (!isNaN(parseInt(i))) {
                out.push(classification_definition.levels_map[i]);
            }
        }
        return out;
    };

    $scope.apply_classification_rules = function () {
        let require_lvl = {};
        let limited_to_group = {};
        let require_group = {};
        let parts_to_check = ['req', 'group', 'subgroup'];

        $scope.disabled_list = {
            "level": {},
            "req": {},
            "group": {},
            "subgroup": {}
        };

        for (let item in classification_definition.params_map) {
            let data = classification_definition.params_map[item];
            if ("require_lvl" in data) {
                require_lvl[item] = data.require_lvl;
            }
            if ("limited_to_group" in data) {
                limited_to_group[item] = data.limited_to_group;
            }
            if ("require_group" in data) {
                require_group[item] = data.require_group;
            }
        }

        for (let part_name in parts_to_check) {
            let part = $scope.active_list[parts_to_check[part_name]];
            for (let key in part) {
                let value = part[key];
                let trigger_auto_select = false;
                if (value) {
                    if (key in require_lvl) {
                        if ($scope.active_list['level_idx'] < require_lvl[key]) {
                            $scope.active_list['level_idx'] = require_lvl[key];
                            $scope.active_list['level'] = {};
                            $scope.active_list['level'][get_c12n_level_text(require_lvl[key], false)] = true;
                        }
                        let levels = $scope.level_list();
                        for (let l_idx in levels) {
                            let l = levels[l_idx];
                            if ($scope.classification_definition.levels_map[l] < require_lvl[key]) {
                                $scope.disabled_list['level'][l] = true;
                            }
                        }
                    }
                    if (key in require_group) {
                        if ($scope.active_list['group'][require_group[key]] !== true) {
                            $scope.active_list['group'][require_group[key]] = true
                        }
                    }
                    if (key in limited_to_group) {
                        for (let g in $scope.classification_definition.groups_map_stl) {
                            if (g !== limited_to_group[key]) {
                                $scope.disabled_list['group'][g] = true;
                                $scope.active_list['group'][g] = false;
                            }
                        }
                    }
                    if (!$scope.maximum_classification && parts_to_check[part_name] === 'group') {
                        trigger_auto_select = true;
                    }
                }
                if (trigger_auto_select) {
                    for (let auto_idx in $scope.classification_definition.groups_auto_select) {
                        $scope.active_list['group'][$scope.classification_definition.groups_auto_select[auto_idx]] = true
                    }
                }
            }
        }
    };

    $scope.$parent.setClassification = function (classification) {
        if (classification == null || classification === "") classification = $scope.classification_definition.UNRESTRICTED;
        let parts = get_c12n_parts(classification, false);

        $scope.active_list = {
            "level_idx": 0,
            "level": {},
            "req": {},
            "group": {},
            "subgroup": {}
        };
        $scope._temp_classification = classification;

        $scope.active_list["level_idx"] = parts['lvl_idx'];
        $scope.active_list["level"][get_c12n_level_text(parts['lvl_idx'], false)] = true;
        for (let r in parts['req']) {
            $scope.active_list["req"][parts['req'][r]] = true;
        }
        for (let g in parts['groups']) {
            $scope.active_list["group"][parts['groups'][g]] = true;
        }
        for (let s in parts['subgroups']) {
            $scope.active_list["subgroup"][parts['subgroups'][s]] = true;
        }
        $scope.apply_classification_rules();
    };

    $scope.toggle = function (item, type) {
        let is_disabled = $scope.disabled_list[type][item];
        if (is_disabled !== undefined && is_disabled) {
            return;
        }

        let current = $scope.active_list[type][item];
        if (current === undefined || !current) {
            if (type === "level") {
                $scope.active_list[type] = {};
                $scope.active_list['level_idx'] = $scope.classification_definition.levels_map[item];
            }
            $scope.active_list[type][item] = true;
        }
        else {
            if (type !== "level") {
                $scope.active_list[type][item] = false;
            }
        }

        $scope.apply_classification_rules();
        $scope.showClassificationText();
    };

    $scope.showClassificationText = function () {
        let parts = {
            'lvl_idx': $scope.active_list.level_idx,
            'req': [],
            'groups': [],
            'subgroups': []
        };

        for (let r_key in $scope.active_list.req) {
            if ($scope.active_list.req[r_key]) {
                parts.req.push(r_key);
            }
        }

        for (let g_key in $scope.active_list.group) {
            if ($scope.active_list.group[g_key]) {
                parts.groups.push(g_key);
            }
        }

        for (let sg_key in $scope.active_list.subgroup) {
            if ($scope.active_list.subgroup[sg_key]) {
                parts.subgroups.push(sg_key);
            }
        }

        $scope._temp_classification = get_c12n_text_from_parts(parts);
    };

    if ($scope.$parent.maximum_classification === undefined) {
        $scope.maximum_classification = false;
    }
    else {
        $scope.maximum_classification = $scope.$parent.maximum_classification;
    }

    $scope.receiveClassification = function (classification_text) {
        $scope.$parent.receiveClassification(classification_text);
    }
});

/***************************************************************************************************
 * ng-utils EXTRA Directives
 */
utils.directive('classificationPicker', function () {
    return {
        templateUrl: '/static/ng-template/class_picker.html',
        replace: true,
        compile: function () {
            return {
                pre: function () {
                },
                post: function () {
                    init_modals();
                    console.log("Classification picker successfully added to the DOM. Modal windows were re-initialized...");
                }
            };
        }
    };
});

/***************************************************************************************************
 * ng-utils EXTRA Filters
 */
utils.filter('class_banner_color', function () {
    return function (s) {
        if (Object.keys(classification_definition).length === 0) return "hidden";
        if (s === undefined || s == null) return "alert-success";

        let split_idx = s.indexOf("//");
        if (split_idx !== -1) {
            s = s.slice(0, split_idx)
        }

        s = get_c12n_text(s, false);

        if (classification_definition.levels_styles_map[s] !== undefined) {
            return classification_definition.levels_styles_map[s].banner;
        }

        return "alert-success";
    }
});

utils.filter('class_label_color', function () {
    return function (s) {
        if (Object.keys(classification_definition).length === 0) return "hidden";
        if (s === undefined || s == null) return "label-default";

        let split_idx = s.indexOf("//");
        if (split_idx !== -1) {
            s = s.slice(0, split_idx)
        }

        s = get_c12n_text(s, false);

        if (classification_definition.levels_styles_map[s] !== undefined) {
            return classification_definition.levels_styles_map[s].label;
        }

        return "label-default";
    }
});

utils.filter('class_long', function () {
    return function (s) {
        if (Object.keys(classification_definition).length === 0) return "";
        if (s === undefined || s == null) s = classification_definition.UNRESTRICTED;
        return get_c12n_text(s);
    }
});

utils.filter('class_sm', function () {
    return function (s) {
        if (Object.keys(classification_definition).length === 0) return "";
        if (s === undefined || s == null) s = classification_definition.UNRESTRICTED;
        return get_c12n_text(s, false);
    }
});

utils.filter('class_text_color', function () {
    return function (s) {
        if (Object.keys(classification_definition).length === 0) return "hidden";
        if (s === undefined || s == null) return "text-muted";
        let split_idx = s.indexOf("//");
        if (split_idx !== -1) {
            s = s.slice(0, split_idx)
        }

        s = get_c12n_text(s, false);

        if (classification_definition.levels_styles_map[s] !== undefined) {
            return classification_definition.levels_styles_map[s].text;
        }

        return "text-muted";
    }
});