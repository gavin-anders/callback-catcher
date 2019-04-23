{% load static %}

var catcherApp = angular.module('catcherApp', ['chart.js', 'ngRoute']);

catcherApp.config(function($locationProvider) {
    $locationProvider.html5Mode(true);
});

catcherApp.run(function($rootScope) {
    $rootScope.prettyJson = function(raw) {
    	var obj = JSON.parse(raw);
        return JSON.stringify(obj, undefined, 4);
    };
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
		
		// route for the clients page
		.when('/clients', {
			templateUrl : '{% static "clients.html" %}',
			controller  : 'clientsController'
		})
});

catcherApp.controller('statusController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {
		$http.get('/api/status/').then(function(response) {
			console.log(response);
			$scope.stats = response.data;
			$scope.pielabels = [];
			$scope.piedata = [];
			for (var k in response.data.fingerprint_callback_count) {
				$scope.pielabels.push(k);
				$scope.piedata.push(response.data.fingerprint_callback_count[k]);
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
			$http.get(url).then(function(response) {
				console.log(response);
				$scope.callbacks = response.data.results;
				$scope.next = response.data.next;
				$scope.previous = response.data.previous;
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
		
		$scope.viewData = function(id) {
			$http({
			     url: '/api/callback/'+id+'/', 
			     method: 'GET'
			}).then(function mySuccess(data) {
				var encodeddata = data.data.data;
				$scope.rawdata = atob(encodeddata);
				new Hexdump(atob(encodeddata), {
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
		    }, function myError(data) {
		    	$scope.message = "Error: loading raw data for callback"
		        console.log(data);
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
		
		$http.get('/api/port/').then(function(response) {
			console.log(response);
			$scope.ports = response.data.results;
			$scope.next = response.data.next;
			$scope.previous = response.data.previous;
		});
		
		$http.get('/api/handler/').then(function(response) {
			console.log(response);
			$scope.handlers = response.data.results;
		});
		
		$scope.viewConfig = function(raw) { 
			$scope.config = $scope.prettyJson(raw);
	    };
	    
	    $scope.editConfig = function() {
	    	$scope.editconfig = $scope.prettyJson($scope.handler.default_config);
			//$scope.settings = pretty;
			//$scope.settingsid = h.id;
		};
		
		$scope.startPort = function() {
			console.log("running startPort");
			try {
				var configdata = JSON.stringify(JSON.parse($scope.editconfig));
			} catch (err) {
				$scope.message = "Invalid configuration string"
				return;
			}
			$http({
			    method: 'POST',
			    url: '/api/port/',
			    data: JSON.stringify({number: $scope.number, protocol: $scope.protocol, ssl: $scope.ssl, handler: $scope.handler.filename, config: configdata}),
		        headers: {'Content-Type': 'application/json'}
			}).then(function successCallback(response) {
				console.log("Service started");
				$http.get('/api/port/').then(function(response) {
					console.log(response);
					$scope.ports = response.data.results;
					$scope.next = response.data.next;
					$scope.previous = response.data.previous;
				});
			}, function errorCallback(response) {
			    console.log('Failed to start service');
			    $scope.message = "Error: Failed to start service";
			});
		};
	    
		$scope.stopPort = function(pk) { 
			$http.delete('/api/port/'+pk+'/')
			   .then(function(response){
			         console.log("Service stopped");
			         $scope.message = "Service stopped successfully";
			         $http.get('/api/port/').then(function(response) {
			 			console.log(response);
			 			$scope.ports = response.data.results;
			 			$scope.next = response.data.next;
			 			$scope.previous = response.data.previous;
			 		});
			       }, function(response){
			    	   console.log("Failed to stop process");
			    	   $scope.message = "Error: Failed to stop service";
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
		$scope.setting_error = '';
		$scope.settingsid = null;
		
		$http.get('/api/handler/').then(function(response) {
			console.log(response);
			$scope.handlers = response.data.results;
			$scope.next = response.data.next;
			$scope.previous = response.data.previous;
		});
		
		$scope.viewConfig = function(raw) { 
			$scope.config = $scope.prettyJson(raw);
	    };
		
		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
		
	}
]);

catcherApp.controller('clientsController', ['$scope', '$location', '$http',
	function($scope, $location, $http) {		
		$http.get('/api/client/').then(function(response) {
			console.log(response);
			$scope.clients = response.data.results;
			$scope.next = response.data.next;
			$scope.previous = response.data.previous;
		});
		
		$scope.addClient = function() {
			$http({
			    method: 'POST',
			    url: '/api/client/',
			    data: JSON.stringify({username: $scope.username, email: $scope.email}),
		        headers: {'Content-Type': 'application/json'}
			}).then(function successCallback(response) {
				console.log(response);
				$scope.message = "New client created: " + response.data.id;
				console.log("New client created: " + response.data.id);
				$http.get('/api/client/').then(function(response) {
					console.log(response);
					$scope.clients = response.data.results;
					$scope.next = response.data.next;
					$scope.previous = response.data.previous;
				});
			}, function errorCallback(response) {
			    console.log('Failed to create client');
			    $scope.message = "Error: Failed to create client";
			});
		};
		
		$scope.generateToken = function(pk) {
			$http({
			    method: 'POST',
			    url: '/api/client/'+pk+'/tokens',
		        headers: {'Content-Type': 'application/json'}
			}).then(function successCallback(response) {
				console.log(response);
				$scope.message = "Token generated";
				console.log("Token generated: " + response.data.token);
				$scope.token = response.data.token;
			}, function errorCallback(response) {
			    console.log('Failed to create new token');
			    $scope.message = "Error: Failed to create new token, try again";
			});
		};
		
		$scope.viewTokens = function(pk) {
			$http.get('/api/client/'+pk+'/tokens').then(function(response) {
				console.log(response);
				$scope.tokens = response.data.results;
				$scope.next = response.data.next;
				$scope.previous = response.data.previous;
			});
		};
		
		$scope.clearTokens = function(pk) {
			$http.delete('/api/client/'+pk+'/tokens')
			   .then(function(response){
			         console.log("Tokens deleted");
			         $scope.message = "Tokens deleted";
			       }, function(response){
			    	   console.log("Failed to clear list of tokens");
			    	   $scope.message = "Error: Failed to delete tokens for " + pk;
			       }
			 );
		};
		
		$scope.deleteClient = function(pk) {
			$http.delete('/api/client/'+pk+'/')
			   .then(function(response){
			         console.log("Client deleted");
			         $http.get('/api/client/').then(function(response) {
							console.log(response);
							$scope.message = "Deleted client " + pk;
							$scope.clients = response.data.results;
							$scope.next = response.data.next;
							$scope.previous = response.data.previous;
						});
			       }, function(response){
			    	   console.log("Failed to delete client");
			    	   $scope.message = "Error: Failed to delete client " + pk;
			       }
			 );
		};
		
		$scope.isMenuActive = function (viewLocation) {
		     var active = (viewLocation === $location.path());
		     return active;
		};
	}
]);

catcherApp.run(function ($rootScope, $window, $http) {
    $rootScope.settingsControl = function ($action) {
        $http({
    	    method: 'POST',
    	    url: '/api/settings/',
    	    data: JSON.stringify({'action': $action}),
            headers: {'Content-Type': 'application/json'}
    	}).then(function successCallback(response) {
    		console.log("Action completed");
    		$scope.message = "Action completed"
    	}, function errorCallback(response) {
    	    console.log('Action failed');
    	});
    };
});

