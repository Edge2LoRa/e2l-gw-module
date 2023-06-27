pub(crate) mod lora_structs {
    use serde_derive::Serialize;
    use serde_derive::Deserialize;

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum RxPks {
        RxpkC(RxpkContent),
        RxpkCK(RxpkContentKerlink),
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RxpkContent
    {
        pub time: Option<String>,
        pub tmst: u32,
        pub freq: f32,
        pub chan: Option<u32>,
        pub stat: Option<i32>,
        pub modu: String,
        pub datr: String,
        pub codr: String,
        pub rssi: Option<i32>,
        pub lsnr: Option<f32>,
        pub size: u32,
        pub data: String,
    }

    /*
    rxpk":[{"aesk":0,"brd":2,"codr":"4/5","data":"QLgAFgCATNkGLGbX832w","datr":"SF7BW125","freq":867.5,"jver":2,"modu":"LORA",],"size":15,"stat":1,"time":"2022-05-27T09:41:21.091993Z","tmst":3593099307}]}
    Rxpk not present in JSON: Error("missing field `chan`", line: 1, column: 507)

     "rsig":[{"ant":0,"chan":2,"etime":"+PeyOghPpvR4YnV9mNJt0w==","foff":3773,"ftdelta":443,"ftstat":0,"ftver":1,"lsnr":-7.0,"rssic":-108,"rssis":-116,"rssisd":0},{"ant":1,"chan":2,"etime":"BIuzSsIZVqi2aCfDYImC6Q==","foff":3786,"ftdelta":270,"ftstat":0,"ftver":1,"lsnr":-9.0,"rssic":-110,"rssis":-120,"rssisd":1}
     */
    #[derive(Debug, Serialize, Deserialize)]
    pub struct RxpkContentKerlink
    {
        pub aesk: u32,
        pub brd: u32,
        pub codr: String,
        pub data: String,
        pub datr: String,
        pub freq: f32,
        pub modu: String,
        pub rsig: Vec<RxpkContentKerlinkAnt>,
        pub size: u32,
        pub stat: i32,
        pub time: Option<String>,
        pub tmst: u32,
    }
    #[derive(Debug, Serialize, Deserialize)]
    pub struct RxpkContentKerlinkAnt
    {
        pub ant: u32,
        pub chan: u32,
        pub etime: String,
        pub foff: u32,
        pub ftdelta: i32,
        pub ftstat: i32,
        pub ftver: i32,
        pub lsnr: f32,
        pub rssic: i32,
        pub rssis: i32,
        pub rssisd: i32,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Rxpk {
        pub(crate) rxpk: Vec<RxpkContent>,
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ForwardProtocols {
    UDP,
    // MQTT,
    // REST,
}

#[derive(Debug, Clone)]
pub struct ForwardInfo<'a> {
    pub dev_addrs : Vec<u32>,
    pub forward_host: &'a str,
    pub port: u16,
    pub forward_protocol: ForwardProtocols,
    pub start_addr: Vec<u32>,
    pub end_addr: Vec<u32>,
    pub start_filter_deveui: Vec<u64>,
    pub end_filter_deveui: Vec<u64>,
}

impl <'a> Default for ForwardInfo<'a> {
    fn default() -> Self {
        ForwardInfo {
            forward_host: "127.0.0.1",
            dev_addrs: vec![],
            forward_protocol: ForwardProtocols::UDP,
            start_addr: vec![0x00_00_00_00],
            port: 1681,
            end_addr: vec![0xFF_FF_FF_FF],
            start_filter_deveui: vec![0x0007ED0000000000],
            end_filter_deveui: vec![0x0007ED0000000FFF],
        }
    }
}
