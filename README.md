# Assemblyline 4 - User Interface

This component provides the User Interface as well as the different APIs and socketio endpoints for the Assemblyline 4 framework.

### UI Components

#### APIs

Assemblyline 4 provides a large set of API that can provide you with all the same information you will find in it's UI and even more. The list of APIs and their functionality is described in the help section of the UI.  

All APIs in Assemblyline output their result in the same manner for consistency:

    {
       "api_response": {},            //Actual response from the API
       "api_error_message": "",       //Error message if it is an error response
       "api_server_version": "4.0.0"  //Assemblyline version and version of the different component
       "api_status_code": 200         //Status code of the response
    }

 **NOTE**: All response codes return this output layout

#### Views

The views are built in layers:

1. It all starts with the python code which takes care of the authentication and loads information about the page and about the user
2. It then passes that information to the Jinja template for the page to be rendered
3. When it reaches the browser, the page in loaded into the angular controller which then in turn calls more APIs to load the data
4. The angular layer loads the data received from the API into angular specific templates to render the page's final components


#### SocketIO endpoints

Assemblyline 4 also provide a list of SocketIO endpoints to get information about the system live. The endpoints will provide authenticated access to many Redis broadcast queues. It is a way for the system to notify user of changes and health of the system without having them to query for that information.

The following queues can be listen on:

* Alerts created
* Submissions ingested
* Health of the system
* State of a given running submission
