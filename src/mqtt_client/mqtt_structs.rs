pub(crate) mod mqtt_structs {
    use std::time::SystemTime;
    use rand::Rng;
    use serde_derive::Serialize;
    use serde_derive::Deserialize;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct MqttVariables {
        pub broker_url: String,
        pub broker_port: String,
        pub broker_auth_name: String,
        pub broker_auth_password: String,
        pub broker_topic: String,


    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct MqttJson {
        pub index : u64,
        pub gwmac : String,
        pub deveui : String,
        pub devaddr : String,
        pub fcnt : u32,
        pub ftype : String,
        pub rssi : i32,
        pub lsnr : f32,
        pub size : u32,
        pub chan: u32,
        pub freq : f32,
        pub datr : String,
        pub tmst : u64,
        pub time : String,
        pub agent_time: u64,
        pub end_line : u64

    }
    impl Default for MqttJson {
        fn default() -> Self {
            MqttJson {
                index: rand::thread_rng().gen_range(0, 18446744073709551615),
                gwmac: "0000000000000000".to_string(),
                deveui: "0000000000000000".to_string(),
                devaddr: "00000000".to_string(),
                fcnt: 0,
                ftype: "Missing".to_string(),
                rssi: 0,
                lsnr: 0.0,
                size: 0,
                chan: 0,
                freq: 0.0,
                datr: "Missing".to_string(),
                tmst: 0,
                time: "2000-01-01T00:00:00.000000Z".to_string(),
                agent_time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() * 1000,
                end_line: 4753416825896106269
            }
        }
    }
}
