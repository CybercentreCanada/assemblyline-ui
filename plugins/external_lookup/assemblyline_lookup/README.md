# Assemblyline 4 - Assemblyline UI Plugin

This UI plugin allows you to pull in information from another Assemblyline instance about tagged IOCs or file hashes to display within Assemblyline.

## Image variants and tags

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

#### Running this component

```bash
docker run --name ui-plugin-lookup-assemblyline cccs/assemblyline-ui-plugin-lookup-assemblyline
```

## Documentation

For more information about this Assemblyline component, follow this [overview](https://cybercentrecanada.github.io/assemblyline4_docs/overview/architecture/) of the system's architecture.

---

# Assemblyline 4 - Assemblyline UI Plugin

Ce plugin d'interface utilisateur vous permet d'extraire de l'information d'une autre instance d'Assemblyline sur les IOCs marqués ou les hashs de fichiers pour les afficher dans Assemblyline.

## Variantes et étiquettes d'image

| **Type d'étiquette** | **Description**                                                                                                  |  **Exemple d'étiquette**   |
| :------------------: | :--------------------------------------------------------------------------------------------------------------- | :------------------------: |
|       dernière       | La version la plus récente (peut être instable).                                                                 |          `latest`          |
|      build_type      | Le type de compilation utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        séries        | Le détail de compilation utilisé, incluant la version et le type de compilation : `version.buildType`.           | `4.5.stable`, `4.5.1.dev3` |

#### Exécuter ce composant

```bash
docker run --name ui-plugin-lookup-assemblyline cccs/assemblyline-ui-plugin-lookup-assemblyline
```

## Documentation

Pour plus d'informations sur ce composant Assemblyline, suivez ce [overview](https://cybercentrecanada.github.io/assemblyline4_docs/overview/architecture/) de l'architecture du système.
