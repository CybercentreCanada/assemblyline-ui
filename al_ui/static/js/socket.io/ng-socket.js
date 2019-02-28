/*
 * Modified version of work from by sgaron
 * angular-socket-io v0.3.0
 * (c) 2014 Brian Ford http://briantford.com
 * License: MIT
 */

'use strict';

angular.module('socket-io', []).
provider('socketFactory', function () {

	// when forwarding events, prefix the event name
	let defaultPrefix = 'socket:';

	// expose to provider
	this.$get = function ($rootScope, $timeout) {

		let asyncAngularify = function (socket, callback) {
			return callback ? function () {
				let args = arguments;
				$timeout(function () {
					callback.apply(socket, args);
				}, 0);
			} : angular.noop;
		};

		return function socketFactory (options) {
			options = options || {};
			let socket = options.ioSocket || io(options.namespace || "", {
				"timeout": 500,
				"transports": ['polling', 'websocket']
			});
			let prefix = options.prefix || defaultPrefix;
			let defaultScope = options.scope || $rootScope;

			socket.on('error', function(error){
				console.log("NG-SocketIO::Failed to connect to:", socket.io.uri);
			});
			socket.on('connect_timeout', function(timeout){
				console.log("NG-SocketIO::Connection timeout reached. (" + timeout + "ms)");
			});
			socket.on('connect', function(){
				console.log("NG-SocketIO::Connected");
			});
			socket.on('reconnecting', function(attempNumber){
				console.log("NG-SocketIO::Reconnecting to SocketIO server. (attempt #"+attempNumber+")");
			});

			let addListener = function (eventName, callback) {
				socket.on(eventName, callback);
				socket.on(eventName, asyncAngularify(socket, callback));
			};

			let setConnectionCallback = function (callback) {
				socket.on('connect', asyncAngularify(socket, callback));
			};

			return {
				connected: function () {
					return socket.socket.connected;
				},

				connecting: function () {
					return socket.socket.connecting;
				},

				on: addListener,
				addListener: addListener,
				setConnectionCallback: setConnectionCallback,

				emit: function (eventName, data, callback) {
					return socket.emit(eventName, data, asyncAngularify(socket, callback));
				},

				removeListener: function () {
					return socket.removeListener.apply(socket, arguments);
				},

				// when socket.on('someEvent', fn (data) { ... }),
				// call scope.$broadcast('someEvent', data)
				forward: function (events, scope) {
					if (events instanceof Array === false) {
						events = [events];
					}
					if (!scope) {
						scope = defaultScope;
					}
					events.forEach(function (eventName) {
						let prefixedEvent = prefix + eventName;
						let forwardBroadcast = asyncAngularify(socket, function (data) {
							scope.$broadcast(prefixedEvent, data);
						});
						scope.$on('$destroy', function () {
							socket.removeListener(eventName, forwardBroadcast);
						});
						socket.on(eventName, forwardBroadcast);
					});
				}
			};
		};
	};
});
