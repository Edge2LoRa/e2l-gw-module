pub(crate) mod mqtt_client {
    use paho_mqtt as mqtt;

    pub struct MqttClient {
        pub broker_url: String,
        pub broker_port: String,
        pub broker_auth_name: String,
        pub broker_auth_password: String,
    }

    impl MqttClient {
        pub fn new(
            broker_url: String,
            broker_port: String,
            broker_auth_name: String,
            broker_auth_password: String,
        ) -> MqttClient {
            MqttClient {
                broker_url,
                broker_port,
                broker_auth_name,
                broker_auth_password,
            }
        }

        pub fn connect(&self) {
            let create_opts = mqtt::CreateOptionsBuilder::new()
                .server_uri(format!("{}:{}", self.broker_url, self.broker_port))
                .client_id("rust_mqtt_client")
                .finalize();

            let mut client = mqtt::AsyncClient::new(create_opts).unwrap_or_else(|e| {
                panic!("Error creating the client: {:?}", e);
            });

            let conn_opts = mqtt::ConnectOptionsBuilder::new()
                .user_name(self.broker_auth_name.clone())
                .password(self.broker_auth_password.clone())
                .finalize();

            let tok = tokio::runtime::Runtime::new().unwrap();
            tok.block_on(async {
                let tok = tokio::runtime::Handle::current();
                let _ = client.connect(conn_opts).await;
                tok.spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                });
            });
        }
    }
}
