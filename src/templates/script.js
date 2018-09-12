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
			templateUrl : '{% static "handler.html" %}',
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
		$scope.message = 'History of incoming connections';
		
		$http.get('/api/callback/').then(function(data) {
			$scope.callbacks = data.data.results;
			$scope.next = data.data.next;
			$scope.previous = data.data.previous;
		});
		
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
	}
]);

catcherApp.controller('handlersController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$scope.message = 'this is the services page';
		
		$http.get('/api/handler/').then(function(data) {
			$scope.handlers = data.data.results;
			$scope.next = data.data.next;
			$scope.previous = data.data.previous;
		});
		
		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
		
	}
]);

catcherApp.controller('servicesController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$scope.message = 'Running and exposed ports.';
		
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
			    alert("Failed to start port");
			});
		};
		
		$scope.stopPort = function(pk) { 
			$http.delete('/api/port/' + pk + '/')
			   .then(function(response){
			         console.log("Service stopped");
			         window.location.reload();
			       }, function(response){
			    	   console.log("Failed to stop process");
			    	   alert("Failed to stop process");
			       }
			    );
	    };

		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
	}
]);
