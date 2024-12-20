[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline--ui-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-ui)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/ui)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:ui)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-ui)](./LICENCE.md)

# Assemblyline 4 - API and Socket IO server

This component provides the User Interface as well as the different APIs and socketio endpoints for the Assemblyline 4 framework.

## Image variants and tags

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Components

### APIs

Assemblyline 4 provides a large set of API that can provide you with all the same information you will find in it's UI and even more. The list of APIs and their functionality is described in the help section of the UI.

All APIs in Assemblyline output their result in the same manner for consistency:

```json
{
  "api_response": {},             //Actual response from the API
  "api_error_message": "",        //Error message if it is an error response
  "api_server_version": "4.0.0",  //Assemblyline version and version of the different component
  "api_status_code": 200          //Status code of the response
}
```

**NOTE**: All response codes return this output layout

#### Running this component

```bash
docker run --name ui cccs/assemblyline-service-ui
```

### SocketIO endpoints

Assemblyline 4 also provide a list of SocketIO endpoints to get information about the system live. The endpoints will provide authenticated access to many Redis broadcast queues. It is a way for the system to notify user of changes and health of the system without having them to query for that information.

The following queues can be listen on:

- Alerts created
- Submissions ingested
- Health of the system
- State of a given running submission

#### Running this component

```bash
docker run --name socketio cccs/assemblyline-service-socketio
```

## Documentation

For more information about this Assemblyline component, follow this [overview](https://cybercentrecanada.github.io/assemblyline4_docs/overview/architecture/) of the system's architecture.

---

# Assemblyline 4 - API et serveur Socket IO

Ce composant fournit l'interface utilisateur ainsi que les différentes API et les points de terminaison Socket IO pour le framework Assemblyline 4.

## Variantes et étiquettes d'image

| **Type d'étiquette** | **Description**                                                                                                                    |  **Exemple d'étiquette**   |
| :------------------: | :--------------------------------------------------------------------------------------------------------------------------------- | :------------------------: |
|       dernière       | La version la plus récente (peut être instable).                                                                                   |          `latest`          |
|      build_type      | Le type de compilation utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. `stable` ou `dev` |     `stable` ou `dev`      |
|        séries        | Le détail de compilation utilisé, incluant la version et le type de compilation : `version.buildType`.                                               | `4.5.stable`, `4.5.1.dev3` |

## Composants

### APIs

Assemblyline 4 fournit un grand nombre d'API qui peuvent vous fournir toutes les informations que vous trouverez dans l'interface utilisateur et même plus. La liste des API et de leurs fonctionnalités est décrite dans la section d'aide de l'interface utilisateur.

Pour des raisons de cohérence, toutes les API d'Assemblyline produisent leurs résultats de la même manière :

```json
{
  "api_response": {},             //Réponse réelle de l'API
  "api_error_message": "",        //Message d'erreur s'il s'agit d'une réponse d'erreur
  "api_server_version": "4.0.0",  //Assemblyline version et version des différents composants
  "api_status_code": 200          //Code d'état de la réponse
}
```

**NOTE** : Tous les codes de réponse renvoient cette présentation de sortie

#### Exécuter ce composant

```bash
docker run --name ui cccs/assemblyline-service-ui
```

### Points d'extrémité SocketIO

Assemblyline 4 fournit également une liste de points de contact SocketIO pour obtenir des informations sur le système en direct. Ces points de contact fournissent un accès authentifié à de nombreuses files d'attente de diffusion Redis. C'est un moyen utilisé par le système pour informer les utilisateurs des changements et de l'état du système sans qu'ils aient à faire des requêtes d'informations.

Les files d'attente suivantes peuvent être écoutées :

- Alertes créées
- Soumissions reçues
- Santé du système
- État d'une soumission en cours

#### Exécuter ce composant

```bash
docker run --name socketio cccs/assemblyline-service-socketio
```

## Documentation

Pour plus d'informations sur ce composant Assemblyline, suivez ce [overview](https://cybercentrecanada.github.io/assemblyline4_docs/overview/architecture/) de l'architecture du système.
