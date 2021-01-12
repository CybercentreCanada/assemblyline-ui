/* global angular */
'use strict';

/***************************************************************************************************
 * toProperCase String prototype
 */
String.prototype.toProperCase = function () {
    return this.replace(/\w\S*/g, function (txt) {
        let full_upper = ["ip", "id", "al", "ts", "md5", "sha1", "sha256", "cc", "bcc", "smtp", "ftp", "http", "pe", "db", "ui", "ttl", "vm", "os", "uid", 'ioc'];
        let full_lower = ["to", "as", "use"];

        if (full_upper.indexOf(txt.toLowerCase()) !== -1) {
            return txt.toUpperCase();
        }

        if (full_lower.indexOf(txt.toLowerCase()) !== -1) {
            return txt.toLowerCase();
        }

        return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
    });
};

String.prototype.toTitleCase = function () {
    return this.replace(/-/g, " ").replace(/_/g, " ").replace(/\./g, " ").toProperCase();
};

String.prototype.breakableStr = function (){
    let outString = String();
    for (let i = 0; i < this.length; i += 4) {
        outString += this.substr(i, 4);
        outString += "\u200b";
    }

    return outString;
}

function arrayBufferToUTF8String(arrayBuffer) {
    try {
        //noinspection JSUnresolvedFunction
        return new TextDecoder("utf-8").decode(new DataView(arrayBuffer));
    }
    catch (ex) {
        return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
    }
}

let entityMap = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "/": "&#x2f;"
};

function escapeHTML(string) {
    return String(string).replace(/[&<>"'\/]/g, function (s) {
        return entityMap[s];
    })
}


let timer = null;

/***************************************************************************************************
 * Utils angular module [ng-utils]
 */
let utils = angular.module('utils', []);

/***************************************************************************************************
 * ng-utils Controllers
 */
utils.controller('imageCtrl', function ($scope) {
    $scope.MAX_TARGET_SIZE = 256;

    //User editing
    $scope.resizeAndCrop = function (dataUrl) {
        let o_img = document.createElement("img");
        let c = document.createElement('canvas');
        let ctx = c.getContext("2d");

        o_img.onload = function(){
            let w = o_img.naturalWidth;
            let h = o_img.naturalHeight;
            let off_x = 0;
            let off_y = 0;
            let t_size = $scope.MAX_TARGET_SIZE;

            if (w > h) {
                off_x = (w - h) / 2;
                w = h;
                if (w < $scope.MAX_TARGET_SIZE) {
                    t_size = w;
                }
            }
            else {
                off_y = (h - w) / 2;
                h = w;
                if (h < $scope.MAX_TARGET_SIZE) {
                    t_size = h;
                }
            }

            c.width = t_size;
            c.height = t_size;

            ctx.drawImage(o_img, off_x, off_y, w, h, 0, 0, t_size, t_size);

            $scope.$parent.current_user.avatar = c.toDataURL();
            $('#avatar').attr("src", $scope.$parent.current_user.avatar);
            $('#remove').removeClass("hide");
            $('#add').addClass("hide");
        };

        o_img.src = dataUrl;
    };

    $scope.removeAvatar = function () {
        $scope.current_user.avatar = null;
        $('#avatar').attr("src", "/static/images/user_default.png");
        $('#remove').addClass("hide");
        $('#add').removeClass("hide");
    };

    $scope.handleFile = function (file) {
        if (!file.type.match(/image.*/)) {
            //This is not an Image file
            console.log(file.type, "is not an image type...");
            return;
        }

        let reader = new FileReader();
        reader.onload = function () {
            $scope.resizeAndCrop(reader.result);
        };
        reader.readAsDataURL(file);
    }


});

utils.controller('pagerCtrl', function ($scope) {
    $scope.tempSearchText = "";

    $scope.$watch('tempSearchText', function (val) {
        if ($scope.$parent.searchText === val) return true;
        $scope.$parent.searchText = $scope.tempSearchText;
    });

    $scope.$watch('rows', function () {
        $scope.$parent.rows = $scope.rows;
        if ($scope.offset === 0 && $scope.$parent.started) {
            $scope.$parent.load_data();
        }
        else {
            $scope.offset = 0;
        }
    });

    $scope.$watch('offset', function () {
        $scope.$parent.offset = $scope.offset;
        if ($scope.$parent.started) {
            $scope.$parent.load_data();
        }
    });

    $scope.load_page = function (page) {
        $scope.offset = (page - 1) * $scope.$parent.rows;
    };

    $scope.pagesToDisplay = function () {
        let idx = ($scope.$parent.offset / $scope.$parent.rows);
        let pages = [];
        let pages_start = 0;
        let pages_end = Math.min($scope.$parent.pages, 7);

        if (idx >= $scope.$parent.pages - 3) {
            pages_start = Math.max($scope.$parent.pages - 7, 0);
            pages_end = $scope.$parent.pages;
        }
        else if (idx > 3) {
            pages_start = idx - 3;
            pages_end = idx + 4;
        }

        for (let i = pages_start; i <= pages_end; i++) {
            pages.push(i + 1);
        }

        return pages;
    };

    $scope.$parent.first = function () {
        if ($scope.$parent.offset !== 0) {
            $scope.offset = 0;
        }
    };

    $scope.$parent.prev = function () {
        if ($scope.$parent.offset !== 0) {
            $scope.offset = $scope.$parent.offset - $scope.$parent.rows;
        }
    };

    $scope.$parent.next = function () {
        if ($scope.$parent.offset / $scope.$parent.rows < $scope.$parent.pages) {
            $scope.offset = $scope.$parent.offset + $scope.$parent.rows;
        }
    };

    $scope.$parent.pagerArray = function () {
        let out = 0;
        if ($scope.$parent.total != null) {
            out = Math.floor($scope.$parent.total / $scope.$parent.rows);
            if (out === Math.ceil($scope.$parent.total / $scope.$parent.rows)) {
                out--;
            }
        }

        return out;
    };

    $scope.$parent.page_switch = function (new_list) {
        $scope.$parent.started = false;
        $scope.$parent.offset = new_list.offset;
        $scope.offset = new_list.offset;
        $scope.$parent.total = new_list.total;
        $scope.$parent.rows = new_list.rows;
        $scope.rows = new_list.rows;
        $scope.$parent.pages = $scope.pagerArray();
        $scope.$parent.cur_list = new_list;
        $scope.$parent.started = true;
    }
});


/***************************************************************************************************
 * ng-utils Directives
 */
utils.directive('alertCard', function () {
    return {
        templateUrl: '/static/ng-template/alert_card.html',
        replace: true
    };
});

utils.directive('alertDetail', function () {
    return {
        templateUrl: '/static/ng-template/alert_card.html',
        replace: true
    };
});

utils.directive('draggable', function () {
    return {
        restrict: 'A',
        link: function (scope, element) {
            element[0].addEventListener('dragstart', scope.handleTagDrag, false);
            element[0].addEventListener('dragend', scope.handleTagDragEnd, false);
        }
    }
});

utils.directive('dockerConfig', function () {
    return {
        scope: {
            docker_config: '=src',
            docker_type: '=type',
            docker_name: '=name',
            docker_volumes: '=volumes'
        },
        templateUrl: '/static/ng-template/docker_config.html'
    }
});

utils.directive('sourceConfig', function () {
    return {
        scope: {
            source_config: '=src',
            service: '='
        },
        templateUrl: '/static/ng-template/source_config.html'
    }
});

utils.directive('dockerConfigEdit', function () {
    return {
        templateUrl: '/static/ng-template/docker_config_edit.html'
    }
});

utils.directive('droppable', function () {
    return {
        restrict: 'A',
        link: function (scope, element) {
            element[0].addEventListener('drop', scope.handleTagDrop, false);
            element[0].addEventListener('dragover', scope.handleTagDragOver, false);
        }
    }
});

utils.directive('errorCard', function () {
    return {
        templateUrl: '/static/ng-template/error_card.html',
        replace: true
    };
});

utils.directive('fileDetail', function () {
    return {
        terminal: true,
        transclude: true,
        templateUrl: '/static/ng-template/file_detail.html'
    }
});

utils.directive('graphSection', function ($window, $timeout) {
    return {
        restrict: 'A',
        require:"ngModel",
        template: "<svg width='100%' height='70'></svg>",
        link: function (scope, elem, attrs, ngModel) {
            scope.render = function () {
                let graph_obj = ngModel.$modelValue;
                let rawSVG = elem.find("svg")[0];

                while (rawSVG.firstChild){
                    rawSVG.removeChild(rawSVG.firstChild)
                }

                if (graph_obj.type === "colormap") {
                    let d3 = $window.d3;
                    let show_legend = graph_obj.data.show_legend;
                    if (show_legend === undefined) {
                        show_legend = true;
                    }
                    let svg = d3.select(rawSVG);
                    let item_width = parseInt(svg.style("width")) / graph_obj.data.values.length;
                    let rect_offset = 0;

                    // Color scale
                    let color_range = ["#87c6fb", "#111920"];
                    let blue_scale = d3.scale.linear().domain(graph_obj.data.domain).range(color_range);

                    if (show_legend) {
                        svg.append("rect")
                            .attr("y", 10)
                            .attr("x", 0)
                            .attr("width", 15)
                            .attr("height", 15)
                            .attr("fill", color_range[0]);

                        svg.append("text")
                            .attr("y", 22)
                            .attr("x", 20)
                            .text(": " + graph_obj.data.domain[0]);

                        svg.append("rect")
                            .attr("y", 10)
                            .attr("x", 80)
                            .attr("width", 15)
                            .attr("height", 15)
                            .attr("fill", color_range[1]);

                        svg.append("text")
                            .attr("y", 22)
                            .attr("x", 100)
                            .text(": " + graph_obj.data.domain[graph_obj.data.domain.length - 1]);

                        rect_offset = 30;
                        svg.attr("height", 70);
                    }

                    for (let x in graph_obj.data.values) {
                        let value = graph_obj.data.values[x];
                        svg.append("rect")
                            .attr("class", "chart_data")
                            .attr("y", rect_offset)
                            .attr("x", x * item_width)
                            .attr("width", item_width + 1)
                            .attr("height", 40)
                            .attr("fill", blue_scale(value));
                    }

                    let w = angular.element($window);

                    let resizeObj = function () {
                        $timeout(function () {
                            let width = parseInt($window.getComputedStyle(elem[0]).width, 10);

                            if (width) {
                                let targetWidth = width / graph_obj.data.values.length;
                                svg.selectAll(".chart_data").each(function (d, i) {
                                    let item = d3.select(this);
                                    item.attr("x", i * targetWidth);
                                    item.attr("width", targetWidth + 1)
                                });
                            } else {
                                resizeObj();
                            }
                        }, 100);
                    };

                    w.bind('resize', function () {
                        resizeObj();
                    });

                    resizeObj();
                }
            };
            scope.$watch(function () { return ngModel.$modelValue; }, scope.render, true);
        }
    }
});

utils.directive('imageDropzone', function () {
    return {
        scope: {
            drop: '='
        },
        link: function (scope, element) {
            let el = element[0];

            el.addEventListener(
                'dragenter',
                function () {
                    this.classList.add('over');
                    return false;
                },
                false
            );

            el.addEventListener(
                'dragover',
                function (e) {
                    e.dataTransfer.dropEffect = 'move';
                    e.stopPropagation();
                    e.preventDefault();
                    this.classList.add('over');
                    return false;
                },
                false
            );

            el.addEventListener(
                'dragleave',
                function () {
                    this.classList.remove('over');
                    return false;
                },
                false
            );

            el.addEventListener(
                'drop',
                function (e) {
                    e.stopPropagation();
                    e.preventDefault();

                    this.classList.remove('over');

                    let dt = e.dataTransfer;
                    let file = dt.files[0];

                    scope.drop(file);

                    return false;
                },
                false
            );
        }
    }
});

utils.directive('imagePreview', function () {
    return {
        templateUrl: '/static/ng-template/img_selector.html'
    }
});

utils.directive('imageSelector', function () {
    return {
        scope: {
            select: '='
        },
        link: function (scope, element) {
            let el = element[0];

            el.addEventListener(
                'change',
                function (e) {
                    let file = e.target.files[0];
                    scope.select(file);
                    return false;
                },
                false
            );
        }
    }
});

utils.directive('integer', function () {
    return {
        restrict: 'A',
        require: 'ngModel',
        link: function (scope, elem, attr, ctrl) {
            ctrl.$parsers.unshift(function (viewValue) {
                return parseInt(viewValue)
            });
        }
    }
});

utils.directive('pager', function () {
    return {
        templateUrl: '/static/ng-template/pager.html'
    }
});

utils.directive('replaceTags', function ($compile) {
    let inline_tag_template = '<span class="inline-tag" style="cursor: pointer;" ng-class="{\'highlight\': isHighlighted(-=TAG=-.type, -=TAG=-.value)}" ng-click="trigger_highlight(-=TAG=-.type, -=TAG=-.value);$event.stopPropagation();" >{{-=TAG=-.value}}</span>';

    function escapeRegExp(string) {
        return string.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1")
    }

    return {
        scope: true,
        link: function (scope, elem, attr) {
            if (scope.$eval(attr.data) == null){
                return null;
            }

            let sec_name = "section_list[sec_info.id]";
            if (scope.$parent.sec_info === undefined){
                sec_name = "sec";
            }

            let data = escapeHTML(scope.$eval(attr.data));
            let tags = scope.$eval(attr.tags);

            for (let i in tags) {
                let tag = tags[i];
                if (tag.value.length > 6) {
                    let re = new RegExp(escapeRegExp(escapeHTML(tag.value)), 'g');
                    data = data.replace(re, inline_tag_template.replace(/-=TAG=-/g, sec_name + '.tags.' + i.toString()));
                }
            }
            elem.html(data);
            $compile(elem.contents())(scope);
        }
    }
});

utils.directive('serviceConfig', function () {
    return {
        templateUrl: '/static/ng-template/service_config.html'
    }
});

utils.directive('signatureDetail', function () {
    return {
        templateUrl: '/static/ng-template/signature_detail.html',
        replace: true
    };
});

utils.directive('signatureSource', function () {
    return {
        templateUrl: '/static/ng-template/signature_source.html'
    };
});

utils.directive('jsonInput', function () {
    return {
        scope: true,
        require: 'ngModel',
        link: function (scope, elem, attr, ngModel) {
            let update_ctrl = null;
            let data = scope.$eval(attr.jsonInput);

            if (data !== undefined && data.update_ctrl !== undefined) {
                //noinspection JSUnusedAssignment
                update_ctrl = getPath(data.update_ctrl);
            }

            function getPath(path) {
                let out = "scope.$parent";
                path = path.split(".");

                while (path.length && (out += "['" + path.shift() + "']")) {
                }

                return out
            }

            function fromUser(text) {
                try {
                    return JSON.parse(text);
                } catch (e) {
                    return text;
                }
            }

            function toUser(my_data) {
                return JSON.stringify(my_data);
            }

            ngModel.$parsers.unshift(fromUser);
            ngModel.$formatters.unshift(toUser);
        }
    }
});

utils.directive('smartInput', function () {
    return {
        scope: true,
        require: 'ngModel',
        link: function (scope, elem, attr, ngModel) {
            let DEBUG = true;
            let splitter = ",";
            let data_type = "string";
            let type_let = null;
            let update_ctrl = null;
            let data = scope.$eval(attr.smartInput);
            if (data !== undefined && data.splitter !== undefined) splitter = data.splitter;
            if (data !== undefined && data.type !== undefined) data_type = data.type;
            if (data !== undefined && data.type_let !== undefined) type_let = data.type_let;
            if (data !== undefined && data.update_ctrl !== undefined) update_ctrl = getPath(data.update_ctrl);
            function updatePath(value) {
                let start = update_ctrl;
                let stop = "";

                let to_apply = update_ctrl;
                if (typeof value == 'string') {
                    to_apply += "='" + value + "'";
                    stop = "'" + value + "'";
                }
                else if (typeof value == "object") {
                    to_apply += "=" + JSON.stringify(value);
                    stop = JSON.stringify(value);
                }
                else {
                    to_apply += "=" + value;
                    stop = value;
                }

                if (DEBUG) eval("console.log(" + start + ", '=>', " + stop + ")");
                eval(to_apply);
            }

            function getPath(path) {
                let out = "scope.$parent";
                path = path.split(".");

                while (path.length && (out += "['" + path.shift() + "']")) {
                }

                return out
            }

            function fromUser(text) {
                let myval;
                if (type_let != null) {
                    let temp_dt = getPath(type_let);
                    eval("data_type = " + temp_dt);
                }

                if (data_type === 'list') {
                    myval = text.split(splitter);
                    for (let idx in myval) {
                        let int_val = parseInt(myval[idx]);
                        if (String(int_val) === myval[idx]) {
                            myval[idx] = int_val;
                        }
                    }
                }
                else if (data_type === 'object') {
                    try {
                        myval = JSON.parse(text);
                    } catch (e) {
                        myval = text;
                    }
                }
                else if (data_type === 'number' || data_type === 'int') {
                    myval = parseFloat(text);
                }
                else if (data_type === 'boolean' || data_type === 'bool') {
                    myval = text === "true";
                }
                else {
                    myval = text;
                }

                if (update_ctrl != null) {
                    updatePath(myval);
                }
                return myval;
            }

            function toUser(array) {
                if (array === undefined) {
                    return "";
                }
                else if (data_type === "list") {
                    return array.join(splitter);
                }
                else if (data_type === "object") {
                    return JSON.stringify(array);
                }
                else {
                    return array
                }
            }

            ngModel.$parsers.unshift(fromUser);
            ngModel.$formatters.unshift(toUser);
        }
    }
});

utils.directive('splitArray', function () {
    return {
        restrict: 'A',
        require: 'ngModel',
        link: function (scope, elem, attr, ngModel) {
            let splitter = ",";
            let data = scope.$eval(attr.splitArray);
            if (data !== undefined && data.splitter !== undefined) splitter = data.splitter;

            function fromUser(text) {
                if (text === ""){
                    return []
                }
                return text.split(splitter);
            }

            function toUser(array) {
                if (array === undefined)
                    return "";
                return array.join(splitter);
            }

            ngModel.$parsers.push(fromUser);
            ngModel.$formatters.push(toUser);
        }
    }
});

utils.directive('kvSection', function () {
    return {
        restrict: 'A',
        require:"ngModel",
        link: function (scope, elem, attrs, ngModel) {
            scope.render = function () {
                let kv_body = ngModel.$viewValue;

                while (elem[0].firstChild){
                    elem[0].removeChild(elem[0].firstChild)
                }
                let table = document.createElement('table');
                for (let key in kv_body) {
                    let tr = document.createElement('tr');
                    tr.setAttribute("class", "kv_line");
                    let value = kv_body[key];

                    let key_td = document.createElement('td');
                    key_td.setAttribute("class", "strong");
                    key_td.style.paddingRight = "25px";
                    key_td.innerText = key.toTitleCase();
                    tr.appendChild(key_td);

                    if (value instanceof Array){
                        value = value.join(" | ");
                    }
                    else if (typeof value === 'object'){
                        value = JSON.stringify(value);
                    }
                    let value_td = document.createElement('td');
                    value_td.innerText = String(value).breakableStr();
                    tr.appendChild(value_td);

                    table.appendChild(tr);
                }
                elem[0].appendChild(table);
            };
            scope.$watch(function () { return ngModel.$modelValue; }, scope.render, true);
        }
    }
});

utils.directive('ncSection', function () {
    return {
        restrict: 'A',
        require:"ngModel",
        link: function (scope, elem, attrs, ngModel) {
            scope.render = function () {
                let nc_body = JSON.parse(ngModel.$viewValue);

                while (elem[0].firstChild){
                    elem[0].removeChild(elem[0].firstChild)
                }
                let div = document.createElement("div");
                div.style.overflowX = "auto";
                div.style.marginRight = "0.5em";
                const isFirst = true;
                process_list(nc_body, div, isFirst);

                function process_list(process_tree, root, isFirst) {
                    let ul = document.createElement("ul");
                    ul.style.listStyleType = "none";
                    if (isFirst === true) {
                        ul.style.marginLeft = "-40px";
                        isFirst = false;
                    }
                    for (let process of process_tree) {
                        // Initial list item element
                        let li = document.createElement("li");

                        // "Container" that will contain the card
                        let card = document.createElement("div");

                        // Process pid details
                        let pid_section = document.createElement("div");
                        pid_section.style.padding = "5px";
                        pid_section.style.backgroundColor = "#EEE";
                        let process_pid = document.createTextNode(process["process_pid"]);
                        pid_section.appendChild(process_pid);

                        let detail_section = document.createElement("div");
                        detail_section.style.padding = "5px";

                        // card header
                        let header = document.createElement("div");
                        header.className = "text-heavy";
                        header.style.paddingBottom = "5px";

                        // Process name details
                        let process_name = document.createTextNode(String(process["process_name"]).breakableStr());
                        header.appendChild(process_name);

                        // card footer
                        let footer = document.createElement("div");

                        // Command line details
                        let samp = document.createElement("samp");
                        let small = document.createElement("small");
                        let cmd = document.createTextNode(String(process["command_line"]).breakableStr());
                        small.appendChild(cmd);
                        samp.appendChild(small);
                        footer.appendChild(samp);

                        // changing the card colour based on how high the total signature score is
                        let signatures = process["signatures"];
                        let total_signature_score = 0;
                        for (let signature in signatures) {
                            total_signature_score += signatures[signature];
                        }
                        if (total_signature_score > 1000) {
                            card.className = "process_card alert-danger";
                        } else if (total_signature_score > 100 && total_signature_score <= 1000) {
                            card.className = "process_card alert-warning";
                        } else {
                            card.className = "process_card alert-light";
                        }

                        // adding a tool tip and message for signatures
                        let sig_section = document.createElement("div");
                        let signature_count = 0;
                        if (signatures !== undefined) {
                            signature_count = Object.keys(signatures).length;
                        }

                        if (signature_count > 0) {
                            let sig_message;
                            if (signature_count === 1) {
                                sig_message = document.createTextNode("Hit 1 signature");
                            } else {
                                sig_message = document.createTextNode("Hit " + signature_count + " signatures");
                            }
                            // Signature section
                            sig_section.style.padding = "5px";
                            // let alert_icon = document.createElement("span");
                            // alert_icon.className = "glyphicon glyphicon-info";
                            let sig_tooltip = document.createElement("div");
                            sig_tooltip.className = "btn";
                            sig_tooltip.title = Object.keys(signatures).join(", ");
                            // sig_tooltip.appendChild(alert_icon);
                            sig_tooltip.appendChild(sig_message);
                            sig_section.appendChild(sig_tooltip);
                        }
                        // Add header and footer to detail section
                        detail_section.appendChild(header);
                        detail_section.appendChild(footer);

                        // Adding the card components
                        card.appendChild(pid_section);
                        card.appendChild(sig_section);
                        card.appendChild(detail_section);

                        // Adding the card to the list
                        li.appendChild(card);
                        ul.append(li);

                        if (process["children"]) {
                            process_list(process["children"], ul, isFirst);
                        }
                    }
                    root.append(ul);
                }

                elem[0].appendChild(div);
            };
            scope.$watch(function () { return ngModel.$modelValue; }, scope.render, true);
        }
    }
});

utils.directive('tableSection', function () {
    return {
        restrict: 'A',
        require:"ngModel",
        link: function (scope, elem, attrs, ngModel) {
            scope.render = function () {
                let table_body = JSON.parse(ngModel.$viewValue);
                while (elem[0].firstChild){
                    elem[0].removeChild(elem[0].firstChild)
                }
                let table = document.createElement('table');
                table.style.width = "100%";
                table.style.marginBottom = "0";
                table.setAttribute("class", "table table-bordered table-condensed table-hover table-striped");

                let thead = table.createTHead();
                let headerRow = thead.insertRow();
                let table_headers = [];

                if(table_body.length > 0){
                    // Create Table Header using union of keys from all dictionaries
                    for (let table_row of table_body) {
                        for (let key in table_row) {
                            let val = table_row[key];
                            // False and 0 are okay
                            if (val !== null && val !== undefined && val!==NaN && val !== "") {
                                if (!table_headers.includes(key)) {
                                    table_headers.push(key);
                                }
                            }
                        }
                    }
                }

                // Creating Table Headers
                for (let key of table_headers) {
                    let th = document.createElement("th");
                    let text = document.createTextNode(key.toTitleCase());
                    th.appendChild(text);
                    th.setAttribute("class", "active");
                    th.style.position = "sticky";
                    th.style.top = "0";
                    th.style.backgroundClip = "padding-box";  // This is necessary because position: sticky removes borders
                    headerRow.appendChild(th);
                }

                // Create Table Body
                let tbody = table.createTBody();
                for (let row of table_body) {
                    let tr = tbody.insertRow();
                    for (let column of table_headers) {
                        let str_value = "";
                        if (column in row) {
                            // Creating nested table
                            if (row[column] !== null && typeof row[column] === 'object') {
                                // Creating table object
                                let nested_table = document.createElement('table');
                                // Copying the key value body format section
                                for (let key in row[column]) {
                                    let val = row[column][key];
                                    if (val === null || val === undefined || val === NaN || val === "") {
                                        continue;
                                    }

                                    let tr = document.createElement('tr');
                                    tr.setAttribute("class", "kv_line");
                                    let value = row[column][key];

                                    let key_td = document.createElement('td');
                                    key_td.setAttribute("class", "strong");
                                    key_td.style.paddingRight = "25px";
                                    key_td.innerText = String(key).toTitleCase();
                                    tr.appendChild(key_td);

                                    if (typeof value === 'object'){
                                        value = JSON.stringify(value);
                                    }
                                    let value_td = document.createElement('td');
                                    value_td.innerText = String(value).breakableStr();
                                    tr.appendChild(value_td);

                                    nested_table.appendChild(tr);
                                }
                                let cell = tr.insertCell();
                                cell.style.padding = "0px";
                                cell.appendChild(nested_table);
                                continue;
                            }
                            else if (row[column] !== null) {
                                str_value = row[column];
                            }
                        }
                        let cell = tr.insertCell();
                        let text = document.createTextNode(String(str_value).breakableStr());
                        cell.appendChild(text);
                    }
                }
                // Responsive table
                let div = document.createElement('div');
                div.setAttribute('class', 'table-responsive');
                div.style.overflowY = "auto";
                div.style.maxHeight = "500px";
                div.appendChild(table);

                elem[0].appendChild(div);
            };
            scope.$watch(function () { return ngModel.$modelValue; }, scope.render, true);
        }
    }
});

utils.directive('urlSection', function () {
    return {
        restrict: 'A',
        require:"ngModel",
        link: function (scope, elem, attrs, ngModel) {
            scope.render = function () {
                let url_body = ngModel.$modelValue;

                while (elem[0].firstChild){
                    elem[0].removeChild(elem[0].firstChild)
                }

                if (Object.prototype.toString.call(url_body) === '[object Array]') {
                    for (let idx in url_body) {
                        let div = document.createElement('div');
                        let cur_url_body = url_body[idx];

                        let a_array = document.createElement('a');
                        a_array.href = cur_url_body.url;
                        if (cur_url_body.name !== undefined) {
                            a_array.text = cur_url_body.name;
                        } else {
                            a_array.text = cur_url_body.url;
                        }
                        div.appendChild(a_array);
                        elem[0].appendChild(div);
                    }
                } else {
                    let a = document.createElement('a');
                    a.href = url_body.url;
                    if (url_body.name !== undefined) {
                        a.text = url_body.name;
                    } else {
                        a.text = url_body.url;
                    }
                    elem[0].appendChild(a);
                }
            };
            scope.$watch(function () { return ngModel.$modelValue; }, scope.render, true);
        }
    }
});

utils.directive('vmConfig', function () {
    return {
        templateUrl: '/static/ng-template/vm_config.html'
    }
});


/***************************************************************************************************
 * ng-utils Filters
 */

utils.filter('breakableStr', function () {
    return function (data) {
        if (data === undefined || data == null) return "";
        let outString = String();
        if (typeof(data) !== "string"){
            data = data.toString();
        }
        return data.breakableStr();
    }
});

utils.filter('fileSize', function () {
    return function (size) {
        if (isNaN(size))
            size = 0;

        if (size < 1024)
            return size + ' Bytes';

        size /= 1024;

        if (size < 1024)
            return size.toFixed(2) + ' Kb';

        size /= 1024;

        if (size < 1024)
            return size.toFixed(2) + ' Mb';

        size /= 1024;

        if (size < 1024)
            return size.toFixed(2) + ' Gb';

        size /= 1024;

        return size.toFixed(2) + ' Tb';
    };
});

utils.filter('floatStr', function () {
    return function (float_let) {
        if (float_let === undefined || float_let == null) return "";
        try {
            return Math.round(float_let * 100) / 100;
        }
        catch (e) {
            return float_let;
        }
    }
});

utils.filter('getErrorTypeFromKey', function () {
    return function (key) {
        let e_id = key.substr(65, key.length);

        if (e_id.indexOf(".e") !== -1) {
            e_id = e_id.substr(e_id.indexOf(".e") + 2, e_id.length);
        }

        if (e_id === "21") {
            return "SERVICE DOWN";
        }
        else if (e_id === "12") {
            return "MAX RETRY REACHED";
        }
        else if (e_id === "10") {
            return "MAX DEPTH REACHED";
        }
        else if (e_id === "30") {
            return "TASK PRE-EMPTED";
        }
        else if (e_id === "20") {
            return "SERVICE BUSY";
        }
        else if (e_id === "11") {
            return "MAX FILES REACHED";
        }
        else if (e_id === "1") {
            return "EXCEPTION";
        }

        return "UNKNOWN";
    }
});

utils.filter('getHashFromKey', function () {
    return function (key) {
        return key.substr(0, 64);
    }
});

utils.filter('getServiceFromKey', function () {
    return function (key) {
        let srv = key.substr(65, key.length);

        if (srv.indexOf(".") !== -1) {
            srv = srv.substr(0, srv.indexOf("."));
        }

        return srv
    }
});

utils.filter('hexDump', function () {
    return function (arrayBuffer) {
        if (arrayBuffer === undefined || arrayBuffer == null) return "";
        let outString = String();
        let pad = "00000000";
        let line = 0;
        let count = 0;
        let data = new Uint8Array(arrayBuffer);

        outString += "00000000:  ";

        for (let i = 0; i < data.length; i++) {
            count++;

            let n = data[i];
            let byteHex = (n < 16) ? "0" + n.toString(16) : n.toString(16);

            outString += byteHex + " ";
            if (count === 16 && i < (data.length - 2)) {
                count = 0;
                line++;
                outString += "\n" + pad.substr(0, 7 - line.toString(16).length) + line.toString(16) + "0:  ";
            }
        }
        return outString
    }
});

utils.filter('hexViewer', function () {
    return function (arrayBuffer) {
        if (arrayBuffer === undefined || arrayBuffer == null) return "";
        let outString = String();
        let pad = "00000000";
        let pad_bytes = "                                                ";
        let line = 0;
        let count = 0;
        let askey = String();
        let data = new Uint8Array(arrayBuffer);

        outString += "00000000: ";
        askey += " ";

        for (let i = 0; i < data.length; i++) {
            count++;

            let n = data[i];
            let byteHex = (n < 16) ? "0" + n.toString(16) : n.toString(16);
            let character = String.fromCharCode(n);

            if (n < 0x20 || n >= 0x7F) {
                character = ".";
            }

            askey += character;
            outString += byteHex + " ";
            if (count === 16 && i < (data.length - 2)) {
                count = 0;
                line++;
                outString += askey + "\n" + pad.substr(0, 7 - line.toString(16).length) + line.toString(16) + "0: ";
                askey = " ";
            }
        }

        if (askey !== " ") {
            outString += pad_bytes.substr(0, 48 - (count * 3)) + askey
        }
        return outString
    }
});

utils.filter('iso_to_utc', function () {
    return function (date, show_suffix) {
        if (show_suffix === undefined){
            show_suffix = false;
        }

        if (date === undefined || date == null) return date;

        if (typeof date === 'string' && date.indexOf('T') === 10 && date.indexOf('Z') === (date.length -1)){
            date = date.replace(/T/g, " ");
            date = date.replace(/Z/g, "");
            if (show_suffix){
                date += " (UTC)"
            }
        }
        return date;
    }
});

utils.filter("joinBy", function () {
    return function (input, delimiter) {
        if (input instanceof Array) {
            return (input || []).join(delimiter || ", ");
        }
        return input;

    }
});

utils.filter('firstLetter', function () {
    return function (data) {
        if (data === undefined || data == null) return "";

        return data[0]
    }
});

utils.filter('maxLength', function () {
    return function (data, length) {
        if (data === undefined || data == null) return "";

        let outString = String();

        if (data.length > length - 3) {
            outString += data.substr(0, length - 3);
            outString += "...";
        }
        else {
            outString += data;
        }

        return outString
    }
});

utils.filter("objectViewer", function () {
    return function (input) {
        if (input instanceof Object){
            let out_list = [];
            for (let key in input){
                let val= input[key];
                if (val instanceof Array) {
                    val = (val || []).join(" | ");
                }
                if (val === "(null)") {
                    val = "";
                }
                out_list.push(key + " => "+ val);
            }
            return out_list.join("\n")
        }

        return input;

    }
});

utils.filter('orderByObjectInt', function () {
    return function (input, attr, l2_attr) {
        if (!angular.isObject(input)) return input;

        let array = [];
        for (let key in input) {
            let item = input[key];
            item.key = key;
            array.push(item);
        }

        array.sort(function (obj_a, obj_b) {
            let a = obj_a[attr];
            let b = obj_b[attr];
            let val = b - a;

            if (val === 0 && l2_attr !== undefined) {
                try {
                    a = obj_a[l2_attr].join();
                } catch (e) {
                    a = obj_a[l2_attr]
                }
                try {
                    b = obj_b[l2_attr].join();
                } catch (e) {
                    b = obj_b[l2_attr];
                }

                if (a > b) {
                    val = 1;
                }
                else if (b > a) {
                    val = -1;
                }
            }

            return val;
        });

        return array;
    }
});

utils.filter('quote', function () {
    return function (data) {
        if (data === undefined || data == null) return "";

        return data.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }
});

utils.filter('rawViewer', function () {
    return function (arrayBuffer) {
        if (arrayBuffer === undefined || arrayBuffer == null) return "";
        let data = arrayBufferToUTF8String(arrayBuffer);

        let outString = String();
        for (let i = 0; i < data.length; i++) {
            let character = data[i];
            let c = data.charCodeAt(i);

            if (c !== 0x9 && c !== 0xa && c !== 0xd && (c < 0x20 || c >= 0x7F)) {
                character = ".";
            }
            outString += character;
        }

        return outString;
    }
});

utils.filter('score_color', function () {
    return function (score) {
        if (score === undefined || score == null) return "text-muted";
        if (score >= 2000) {
            return "text-danger";
        }
        else if (score >= 500) {
            return "text-warning";
        }
        else if (score >= 100) {
            return "text-info";
        }
        else if (score < 0) {
            return "text-success";
        }
        else {
            return "text-muted";
        }
    }
});

utils.filter('section_color', function () {
    return function (score) {
        if (score === undefined || score == null) return "section_info";
        if (score >= 1000) {
            return "section_malicious";
        }
        else if (score >= 100) {
            return "section_suspicious";
        }
        else if (score < 0) {
            return "section_safe";
        }
        else {
            return "section_info";
        }
    }
});

utils.filter('label_color', function () {
    return function (score) {
        if (score === undefined || score == null) return "label-heur-info";
        if (score >= 1000) {
            return "label-heur-malicious";
        }
        else if (score >= 100) {
            return "label-heur-suspicious";
        }
        else if (score < 0) {
            return "label-heur-safe";
        }
        else {
            return "label-heur-info";
        }
    }
});

utils.filter('score_label', function () {
    return function (score) {
        if (score === undefined || score == null) return "Info";
        if (score >= 1000) {
            return "Malicious";
        }
        else if (score >= 100) {
            return "Suspicious";
        }
        else if (score < 0) {
            return "Safe";
        }
        else {
            return "Info";
        }
    }
});

utils.filter('verdict_text_color', function () {
    return function (score) {
        if (score === undefined || score == null) return "text-muted";
        if (score >= 2000) {
            return "text-danger";
        }
        else if (score >= 500) {
            return "text-warning2";
        }
        else if (score >= 100) {
            return "text-info";
        }
        else if (score < 0) {
            return "text-success";
        }
        else {
            return "text-muted";
        }
    }
});

utils.filter('verdict_color', function () {
    return function (score) {
        if (score === undefined || score == null) return "label-default";
        if (score >= 2000) {
            return "label-danger";
        }
        else if (score >= 500) {
            return "label-warning";
        }
        else if (score >= 100) {
            return "label-info";
        }
        else if (score < 0) {
            return "label-success";
        }
        else {
            return "label-default";
        }
    }
});

utils.filter('verdict', function () {
    return function (score) {
        if (score === undefined || score == null) return "Non-Malicious";
        if (score >= 2000) {
            return "Malicious";
        }
        else if (score >= 500) {
            return "Highly Suspicious";
        }
        else if (score >= 100) {
            return "Suspicious";
        }
        else if (score < 0) {
            return "Safe";
        }
        else {
            return "Non-Malicious";
        }
    }
});

utils.filter('sortList', function () {
    return function (input) {
        if (input != null) {
            return input.sort();
        }
    }
});

utils.filter('split', function () {
    return function (data) {
        let splitter = " | ";
        try {
            return data.join(splitter);
        }
        catch (e) {
            return data;
        }
    }
});

utils.filter('splitHex', function () {
    return function (data) {
        if (data === undefined || data == null) return "";
        let outString = String();
        let pad = "00000000";
        let line = 0;
        let count = 0;

        outString += "00000000  ";

        for (let i = 0; i < data.length; i += 2) {
            count++;
            let byteHex = data.substr(i, 2);
            outString += byteHex + " ";
            if (count === 16 && i < (data.length - 2)) {
                count = 0;
                line++;
                outString += "\n" + pad.substr(0, 7 - line.toString(16).length) + line.toString(16) + "0  ";
            }
        }
        return outString
    }
});

utils.filter('stringViewer', function () {
    return function (arrayBuffer) {
        if (arrayBuffer === undefined || arrayBuffer == null) return "";
        let data = arrayBufferToUTF8String(arrayBuffer);
        let res = data.match(/[\x1f-\x7e]{6,}/g);

        return res.join("\n")
    }
});

utils.filter('stripNull', function () {
    return function (val) {
        if (val === "(null)") {
            return "";
        }

        return val;
    }
});

utils.filter('shortTagType', function () {
    return function (input) {
        let idx = input.lastIndexOf('.');

        return input.slice(idx, input.length);
    }
});

utils.filter('titleCase', function () {
    return function (input) {
        if (input === null || input === undefined){
            return input
        }
        return input.toTitleCase()
    }
});

utils.filter('unit', function () {
    return function (bytes, precision) {
        if (isNaN(parseFloat(bytes)) || !isFinite(bytes)) return "-";
        if (precision === undefined) precision = 1;
        let units = ['bytes', 'kB', 'MB', 'GB', 'TB', 'PB'],
            number = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, Math.floor(number))).toFixed(precision) + " " + units[number];
    }
});

utils.filter('utc_date', function () {
    return function (date) {
        let cur_date = new Date(date);
        return new Date(cur_date.getUTCFullYear(), cur_date.getUTCMonth(), cur_date.getUTCDate(), cur_date.getUTCHours(), cur_date.getUTCMinutes(), cur_date.getUTCSeconds());
    }
});
