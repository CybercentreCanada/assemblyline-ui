# Assemblyline 4 UI

This component provides the User Interface as well as the different APIs for the assemblyline 4 framework.

## UI Components

### NGinx

The assemblyline UI uses NGinx as the web proxy. It performs the following tasks:

* Serve and cache the static files
* Perform Client certificate authentication against the cert CAs
* Route the users between the production and development Web and SocketIO servers

### uWsgi

uWsgi is used to serve the different python APIs and views.

###### APIs

All APIs in assemblyline output their result in the same manner:

    {
       "api_response": {},            //Actual response from the API
       "api_error_message": "",       //Error message if it is an error response
       "api_server_version": "4.0.0"  //Assemblyline version and version of the different component
       "api_status_code": 200         //Status code of the response
    }

 **NOTE**: All response codes return this output layout

###### Views

The uWsgi views are built in layers:

1. It all starts with the python code which takes care of the authentication and loads information about the page and about the user
2. It then passes that information to the Jinja template for the page to be rendered.
3. When it reaches the browser, the page in loaded into the angular controller which then in turn calls more APIs to load the data
4. The angular layer loads the data received from the API into angular specific templates to render the page's final components


### Gunicorn

Gunicorn is used as the SocketIO server. This server will provide authenticated access to many Redis broadcast queues. It is a way for the system to notify user of changes and health of the system without having them to query for that information.

The following queues can be listen on:

* Alerts created
* Submissions ingested
* Health of the system
* State of a given running submission
