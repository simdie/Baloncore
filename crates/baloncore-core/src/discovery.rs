use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaDiscoveryTarget {
    pub base_url: String,
    pub schema_paths: Vec<SchemaProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaProbe {
    pub schema_type: SchemaType,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SchemaType {
    OpenApi,
    GraphQl,
    Postman,
    Wsdl,
    GrpcReflection,
}

pub fn default_schema_probes() -> Vec<SchemaProbe> {
    [
        (SchemaType::OpenApi, "/swagger.json"),
        (SchemaType::OpenApi, "/swagger.yaml"),
        (SchemaType::OpenApi, "/openapi.json"),
        (SchemaType::OpenApi, "/openapi.yaml"),
        (SchemaType::OpenApi, "/api-docs"),
        (SchemaType::OpenApi, "/api/docs"),
        (SchemaType::OpenApi, "/v2/api-docs"),
        (SchemaType::OpenApi, "/v3/api-docs"),
        (SchemaType::GraphQl, "/graphql"),
        (SchemaType::GraphQl, "/api/graphql"),
        (SchemaType::Postman, "/postman/collection.json"),
        (SchemaType::Wsdl, "/?wsdl"),
        (
            SchemaType::GrpcReflection,
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        ),
    ]
    .into_iter()
    .map(|(schema_type, path)| SchemaProbe {
        schema_type,
        path: path.to_string(),
    })
    .collect()
}
