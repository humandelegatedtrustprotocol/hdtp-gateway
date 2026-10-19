# testdata

Three files of [google/A2UI](https://github.com/google/A2UI)'s `specification/v0_9_1`, at commit
`cbaa5ee6`, copied unchanged under its Apache License 2.0:

| File here | A2UI's |
|---|---|
| `a2ui-v0_9_1-basic-catalog.json` | `catalogs/basic/catalog.json` |
| `a2ui-v0_9_1-common_types.json` | `json/common_types.json` |
| `a2ui-v0_9_1-server_to_client.json` | `json/server_to_client.json` |

`TestTheCatalogIsA2UIsBasicCatalogNarrowed` holds the node's catalog to the basic catalog, and
`TestEverySurfaceTheNodeTakesIsA2UIByA2UIsOwnSchema` validates every surface the node takes against
A2UI's own message schema, in a catalog of the basic components and the node's KeyValue.
