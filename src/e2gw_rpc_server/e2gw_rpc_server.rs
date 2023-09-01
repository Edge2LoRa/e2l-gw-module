pub(crate) mod e2gw_rpc_server {
    extern crate p256;
    use tonic::{Request, Response, Status};

    use self::edge2_gateway_server::Edge2Gateway;

    // Include the generated proto file
    tonic::include_proto!("edge2gateway");

    #[derive(Debug, Default)]
    pub struct MyEdge2GatewayServer {}

    #[tonic::async_trait]
    impl Edge2Gateway for MyEdge2GatewayServer {
        async fn handle_ed_pub_info(
            &self,
            request: Request<EdPubInfo>,
        ) -> Result<Response<GwInfo>, Status> {
            println!("Got a request: {:?}", request);
            let inner_request = request.into_inner();
            let _dev_eui = inner_request.dev_eui;
            let _dev_addr = inner_request.dev_addr;
            let _g_as_ed = inner_request.g_as_ed;
            let _dev_public_key = inner_request.dev_public_key;
            let reply = GwInfo {
                status_code: 0,
                g_gw_ed: "aa".into(),
            };
            Ok(Response::new(reply))
        }
    }
}
