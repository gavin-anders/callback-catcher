{% load static %}

var catcherApp = angular.module('catcherApp', ['chart.js', 'ngRoute']);

catcherApp.config(function($locationProvider) {
    $locationProvider.html5Mode(true);
});

// configure our routes
catcherApp.config(function($routeProvider) {
	$routeProvider

		// route for the home page
		.when('/', {
			templateUrl : '{% static "status.html" %}',
			controller  : 'statusController'
		})
		
		// route for the home page
		.when('/callbacks', {
			templateUrl : '{% static "callbacks.html" %}',
			controller  : 'callbackController'
		})

		// route for the services page
		.when('/ports', {
			templateUrl : '{% static "ports.html" %}',
			controller  : 'servicesController'
		})
		
		// route for the handlers page
		.when('/handlers', {
			templateUrl : '{% static "handlers.html" %}',
			controller  : 'handlersController'
		})
});

catcherApp.controller('statusController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$http.get('/api/status/').then(function(data) {
			$scope.stats = data.data;
			
			$scope.pielabels = [];
			$scope.piedata = [];
			for (var k in data.data.fingerprint_callback_count) {
				$scope.pielabels.push(k);
				$scope.piedata.push(data.data.fingerprint_callback_count[k]);
			};
		});
		
		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
	}
]);

catcherApp.controller('callbackController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$scope.message = '';
		
		$scope.getList = function(url) {
			$http.get(url).then(function(data) {
				console.log(data);
				$scope.callbacks = data.data.results;
				$scope.next = data.data.next;
				$scope.previous = data.data.previous;
			});
		};
		
		$scope.nextPage = function(){
			console.log($scope.next);
			$scope.getList($scope.next);
		};
		$scope.previousPage = function(){
			$scope.getList($scope.previous);
		};
				
		$scope.message = '';
		$scope.lookups = [];
		$scope.queries = [];
		$scope.fields = [{
			  id: 0,
			  label: 'Source IP',
			  name: 'ip',
			  lookups: ['contains', 'exact']
			}, {
			  id: 1,
			  label: 'Port',
			  name: 'port',
			  lookups: ['contains', 'exact']
			}, {
			  id: 2,
			  label: 'Protocol',
			  lookups: ['contains', 'exact']
			}, {
			  id: 3,
			  label: 'Data',
			  name: 'data',
			  lookups: ['contains', 'exact']
			}, {
			  id: 4,
			  label: 'Timestamp',
			  name: 'timestamp',
			  lookups: ['timestamp_before', 'timestamp_after']
			}];
		
		$scope.executeQuery = function() {
			// ?ip=&ip_lookup=&port=&port_lookup=&protocol=&timestamp_after=&timestamp_before=&fingerprint=&data=&data_lookup=
			var p = {};
			for (q of $scope.queries) {
				var lookup_name = q.field.name + '_lookup';
				p[lookup_name] = q.lookup;
				p[q.field.name] = q.value;
			};
			$http({
			     url: '/api/callback/', 
			     method: 'GET',
			     params: p
			}).then(function mySuccess(data) {
				$scope.callbacks = data.data.results;
				$scope.next = data.data.next;
				$scope.previous = data.data.previous;
		    }, function myError(data) {
		        console.log(data);
		    });
		};
		
		$scope.addRow = function() {
			var f = {field: $scope.newfield, lookup: $scope.newlookup, value: $scope.newvalue};
			console.log($scope.newfield.id);
			$scope.queries.splice($scope.newfield.id, 0, f);
			console.log($scope);
		};
		$scope.removeRow = function($q) { 
			console.log($q.index);
			$scope.queries.splice($q.index, 1); 
		};
		$scope.setLookups = function($l) { $scope.lookups = $l.lookups; };
		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
		
		$scope.viewData = function($d) {
	        $scope.rawdata = atob($d);
	        new Hexdump(atob($d), {
	            container: 'hexdump'
	            , base: 'hex'
	            , width: 16
	            , ascii: false
	            , byteGrouping: 16
	            , html: true
	            , lineNumber: false
	            , style: {
	                lineNumberLeft: ''
	              , lineNumberRight: ':'
	              , stringLeft: '|'
	              , stringRight: '|'
	              , hexLeft: ''
	              , hexRight: ''
	              , hexNull: '00'
	              , stringNull: '.'
	            }
	          });
	     };
	     
	     $scope.viewSecrets = function($data) { 
	    	 $scope.secrets = $data;
	     };
	     
	     $scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
	     };
	     
	     $scope.getList('/api/callback/');
	}
]);

catcherApp.controller('servicesController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$scope.message = '';
		
		$http.get('/api/port/').then(function(data) {
			$scope.ports = data.data.results;
			$scope.next = data.data.next;
			$scope.previous = data.data.previous;
		});
		
		$http.get('/api/handler/').then(function(data) {
			$scope.handlers = data.data.results;
		});
		
		$scope.startPort = function() {
			console.log("running startPort");
			console.log($scope.number);
			$http({
			    method: 'POST',
			    url: '/api/port/',
			    data: JSON.stringify({number: $scope.number,protocol: $scope.protocol,ssl: $scope.ssl,handler: $scope.handler}),
		        headers: {'Content-Type': 'application/json'}
			}).then(function successCallback(response) {
				console.log("Service started");
				window.location.reload();
			}, function errorCallback(response) {
			    console.log('Failed to start port');
			    $scope.message = "Error: Failed to start port";
			});
		};
		
		$scope.stopPort = function(pk) { 
			$http.delete('/api/port/' + pk + '/')
			   .then(function(response){
			         console.log("Service stopped");
			         window.location.reload();
			       }, function(response){
			    	   console.log("Failed to stop process");
			    	   $scope.message = "Error: Failed to stop process";
			       }
			    );
	    };

		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
	}
]);

catcherApp.controller('handlersController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$scope.message = '';
		$scope.setting_error = '';
		$scope.settingsid = null;
		
		$http.get('/api/handler/').then(function(data) {
			$scope.handlers = data.data.results;
			$scope.next = data.data.next;
			$scope.previous = data.data.previous;
		});
		
		$scope.editSettings = function(h) {
			$scope.settings = h.settings;
			$scope.settingsid = h.id;
		};
		
		$scope.saveSettings = function() {
			console.log($scope.settings);
			$http({
			    method: 'PATCH',
			    url: '/api/handler/' + $scope.settingsid + '/',
			    data: {"settings" : $scope.settings},
		        headers: {'Content-Type': 'application/json'}
			}).then(function successHandler(response) {
				console.log("Handler updated");
				$scope.message = "Handler updated";
			}, function errorHandler(response) {
			    console.log('Failed to edit handler');
			    $scope.message = "Error: Failed to edit handler";
			});
			$scope.edit_handler = null;
		};
		
		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
		
	}
]);
