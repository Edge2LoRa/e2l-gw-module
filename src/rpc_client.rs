use hello_world::data_client::DataClient;
use hello_world::DataRequest;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}
