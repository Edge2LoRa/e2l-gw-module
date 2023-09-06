pub(crate) mod e2gw_rpc_server {
    use crate::e2l_crypto::e2l_crypto::E2L_CRYPTO;

    // RPC
    use self::edge2_gateway_server::Edge2Gateway;
    use tonic::{Request, Response, Status};

    // Include the generated proto file
    tonic::include_proto!("edge2gateway");

    pub struct MyEdge2GatewayServer {}

    #[tonic::async_trait]
    impl Edge2Gateway for MyEdge2GatewayServer {
        async fn handle_ed_pub_info(
            &self,
            request: Request<EdPubInfo>,
        ) -> Result<Response<GwInfo>, Status> {
            println!("Got a request: {:?}", request);
            let inner_request = request.into_inner();
            let dev_eui = inner_request.dev_eui;
            let dev_addr = inner_request.dev_addr;
            let g_as_ed_compressed = inner_request.g_as_ed;
            let dev_public_key_compressed = inner_request.dev_public_key;
            unsafe {
                let g_gw_ed_compressed = E2L_CRYPTO.handle_ed_pub_info(
                    dev_eui,
                    dev_addr,
                    g_as_ed_compressed,
                    dev_public_key_compressed,
                );
                let reply = GwInfo {
                    status_code: 0,
                    g_gw_ed: g_gw_ed_compressed,
                };
                Ok(Response::new(reply))
            }
        }
    }
}
