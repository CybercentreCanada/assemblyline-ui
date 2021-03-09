# Assemblyline 4 - API and Socket IO server

This component provides the User Interface as well as the different APIs and socketio endpoints for the Assemblyline 4 framework.

### Components

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

#### SocketIO endpoints

Assemblyline 4 also provide a list of SocketIO endpoints to get information about the system live. The endpoints will provide authenticated access to many Redis broadcast queues. It is a way for the system to notify user of changes and health of the system without having them to query for that information.

The following queues can be listen on:

* Alerts created
* Submissions ingested
* Health of the system
* State of a given running submission
