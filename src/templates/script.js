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
			$scope.callbacks = data.data;
		});
		
		$scope.viewData = function($d) {
	        $scope.rawdata = atob($d);
	        new Hexdump(atob($d), {
	            container: 'hexdump'
	            , base: 'hexadecimal'
	            , width: 16
	            , ascii: true
	            , byteGrouping: 0
	            , html: true
	            , lineNumber: true
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
		
		$http.get('/api/handler').then(function(data) {
			$scope.handlers = data;
		});
		
		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
	}
]);

catcherApp.controller('servicesController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$scope.message = 'this is the services page';
		
		$http.get('/api/port').then(function(data) {
			$scope.services = data;
		});

		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
	}
]);
