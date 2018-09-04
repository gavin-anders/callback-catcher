

// create the module and name it catcherApp
	var catcherApp = angular.module('catcherApp', ['ngRoute']);

	// configure our routes
	catcherApp.config(function($routeProvider) {
		$routeProvider

			// route for the home page
			.when('/', {
				templateUrl : 'pages/status.html',
				controller  : 'statusController'
			})
			
			// route for the home page
			.when('/callbacks', {
				templateUrl : 'pages/callbacks.html',
				controller  : 'callbackController'
			})

			// route for the services page
			.when('/services', {
				templateUrl : 'pages/ports.html',
				controller  : 'servicesController'
			})
			
			// route for the handlers page
			.when('/handlers', {
				templateUrl : 'pages/handlers.html',
				controller  : 'handlersController'
			})
	});

	catcherApp.controller('statusController', ['$scope', '$location', '$http',
		function($scope, $location, $http) {
			$http.get('/api/status/').success(function(data) {
				console.log(data);
				$scope.stats = data.stats;
				$scope.percentages = data.percentages;
				$scope.ipaddresses = data.ipaddresses;
			});
			
			$scope.isMenuActive = function (viewLocation) {
			     var active = (viewLocation === $location.path());
			     return active;
			};
		}
	]);
	
	catcherApp.controller('callbackController', ['$scope', '$location', '$http',
		function($scope, $location, $http) {
			$scope.message = 'this is the callbacks';
			
			$http.get('/api/callback').success(function(data) {
				$scope.callbacks = data;
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
		     
		     $scope.isMenuActive = function (viewLocation) {
			     var active = (viewLocation === $location.path());
			     return active;
		     };
		}
	]);

	catcherApp.controller('handlersController', ['$scope', '$location', '$http',
		function($scope, $location, $http) {
			$scope.message = 'this is the services page';
			
			$http.get('/api/handler').success(function(data) {
				$scope.handlers = data;
			});
			
			$scope.addHandler = function() {
				$http({
			        method : "POST",
			        url : "/api/handlers",
			        data : $scope.handler
			    }).then(function mySuccess(response) {
			        $scope.message = "Added new handler";
			        $scope.handlers = response.data;
			    }, function myError(response) {
			        $scope.message = response.statusText;
			    });
			};
			
			$scope.deleteHandler = function($id) {
				console.log("delete handler called");
				$http({
			        method : "DELETE",
			        url : "/api/handlers",
			        data : {"id": $id},
			    }).then(function mySuccess(response) {
			        $scope.message = "Deleted handler";
			        $scope.handlers = response.data;
			    }, function myError(response) {
			        $scope.message = response.statusText;
			    });
			};
			
			$http.get('/api/handlers').success(function(data) {
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
			
			$http.get('/api/port').success(function(data) {
				$scope.services = data;
			});
			
			$scope.addService = function() {
				$http({
			        method : "POST",
			        url : "/api/ports",
			        data : $scope.services
			    }).then(function mySuccess(response) {
			        $scope.message = "Added new service";
			        $scope.services = response.data;
			    }, function myError(response) {
			        $scope.message = response.statusText;
			    });
			};
			
			$scope.editService = function() {
				$http({
			        method : "PUT",
			        url : "/api/ports",
			        data : $scope.services
			    }).then(function mySuccess(response) {
			        $scope.message = "Edited service";
			        $scope.services = response.data;
			    }, function myError(response) {
			        $scope.message = response.statusText;
			    });
			};
			
			$scope.deleteService = function($id) {
				console.log("delete services called");
				$http({
			        method : "DELETE",
			        url : "/api/ports",
			        data : {"id": $id},
			    }).then(function mySuccess(response) {
			        $scope.message = "Deleted service";
			        $scope.services = response.data;
			    }, function myError(response) {
			        $scope.message = response.statusText;
			    });
			};
			
			$http.get('/api/handlers').success(function(data) {
				$scope.handlers = data;
			});
			
			$scope.isMenuActive = function (viewLocation) {
			     var active = (viewLocation === $location.path());
			     return active;
			};
		}
	]);
