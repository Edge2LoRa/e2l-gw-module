mod e2gw_rpc_client;
mod json_structs;
mod lorawan_structs;
mod mqtt_client;

#[macro_use]
extern crate lazy_static;
extern crate base64;
extern crate core;
extern crate dotenv;
extern crate getopts;
extern crate lorawan_encoding;
extern crate rand;
extern crate rumqttc;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;

extern crate local_ip_address;
// extern crate elliptic_curve;
extern crate p256;

// E2L
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::init_rpc_client;
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::E2gwPubInfo;
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::NewDataRequest;

// ECC
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::PublicKey as P256PublicKey;
use p256::elliptic_curve::SecretKey as P256SecretKey;

use json_structs::filters_json_structs::filter_json::{EnvVariables, FilterJson};
use lorawan_encoding::keys::AES128;
use lorawan_encoding::parser::{
    parse, AsPhyPayloadBytes, DataHeader, DataPayload, MHDRAble, MType, PhyPayload,
};
use lorawan_structs::lorawan_structs::lora_structs::{Rxpk, RxpkContent};
use lorawan_structs::lorawan_structs::{ForwardInfo, ForwardProtocols};
use mqtt_client::mqtt_structs::mqtt_structs::{MqttJson, MqttVariables};
use rand::Rng;
use rumqttc::{Client, MqttOptions, QoS};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::{self};
// use std::io::Read;
use std::net::UdpSocket;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use std::time::{SystemTime, UNIX_EPOCH};

const TIMEOUT: u64 = 3 * 60 * 100;
static mut DEBUG: bool = false;

// EDGE COUNTER
static mut E2FRAME_DATA: Vec<i8> = vec![];
const E2FRAME_DATA_MAX_SIZE: usize = 5;

// #[derive(Debug, Serialize, Deserialize)]
// enum Value {
//     Null,
//     Bool(bool),
//     Number(Number),
//     String(String),
//     Array(Vec<Value>),
//     HashSet(HashSet<String, Value>),
// }

lazy_static! {
    static ref PACKETNAMES: HashMap<u8, &'static str> = {
        let mut m = HashMap::new();
        m.insert(0, "PUSH_DATA");
        m.insert(1, "PUSH_ACK");
        m.insert(2, "PULL_DATA");
        m.insert(3, "PULL_RESP");
        m.insert(4, "PULL_ACK");
        m.insert(5, "TX_ACK");
        m
    };
    static ref COUNT: usize = PACKETNAMES.len();
}

struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }
}

// You can choose to implement multiple traits, like Lower and UpperHex
impl Display for HexSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want to pad the value or have spaces inbetween, etc.
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}

trait HexDisplayExt {
    fn hex_display(&self) -> HexSlice<'_>;
}

impl<T> HexDisplayExt for T
where
    T: ?Sized + AsRef<[u8]>,
{
    fn hex_display(&self) -> HexSlice<'_> {
        HexSlice::new(self)
    }
}

fn get_data_from_json(from_upstream: &[u8]) -> Rxpk {
    // Some JSON input data as a &str. Maybe this comes from the user.
    let data_string = str::from_utf8(from_upstream).unwrap();
    debug(format!("{}", data_string));
    let data: Rxpk = match serde_json::from_str(data_string) {
        Ok(data) => data,
        Err(e) => {
            debug(format!("Rxpk not present in JSON: {:?}", e));
            Rxpk { rxpk: vec![] }
        }
    };
    data
}

fn build_json_for_broker(
    idx: u64,
    gw_mac: String,
    data: &RxpkContent,
    fcnt: Option<u16>,
    mtype: MType,
    dev_addr: Option<u32>,
    dev_eui: Option<u64>,
) -> String {
    let mut mqtt_json = MqttJson::from(data);
    mqtt_json.index = idx;
    if dev_addr.is_some() {
        mqtt_json.devaddr = Some(format!("{:x}", dev_addr.unwrap()).to_string()).unwrap();
    }
    if dev_eui.is_some() {
        mqtt_json.deveui = Some(format!("{:x}", dev_eui.unwrap()).to_string()).unwrap();
    }
    mqtt_json.gwmac = gw_mac;
    if fcnt.is_some() {
        mqtt_json.fcnt = fcnt.unwrap() as u32;
    }
    if data.time.is_some() {
        mqtt_json.time = data.time.clone().unwrap();
    }

    mqtt_json.ftype = format!("{:?}", mtype);
    mqtt_json.size = data.size;
    mqtt_json.end_line = 1;
    let json_to_send = serde_json::to_string_pretty(&mqtt_json).unwrap();

    return json_to_send;
}

impl From<&RxpkContent> for MqttJson {
    fn from(m: &RxpkContent) -> Self {
        let rssi_clone: i32;
        if m.rssi.is_some() {
            rssi_clone = m.rssi.unwrap();
        } else {
            rssi_clone = 0;
        }

        let lsnr_clone: f32;
        if m.lsnr.is_some() {
            lsnr_clone = m.lsnr.unwrap();
        } else {
            lsnr_clone = 0.0;
        }

        let chan_clone: u32;
        if m.chan.is_some() {
            chan_clone = m.chan.unwrap();
        } else {
            chan_clone = 0;
        }

        Self {
            rssi: rssi_clone,
            lsnr: lsnr_clone,
            chan: chan_clone,
            freq: m.freq,
            datr: m.datr.clone(),
            tmst: m.tmst as u64 * 1000,
            ..Default::default()
        }
    }
}

/*fn print_usage(program: &str, opts: Options) {
    let program_path = std::path::PathBuf::from(program);
    let program_name = program_path.file_stem().unwrap().to_str().unwrap();
    let brief = format!(
        "Usage: {} [-b BIND_ADDR] -l LOCAL_PORT -h REMOTE_ADDR -r REMOTE_PORT",
        program_name
    );
    print!("{}", opts.usage(&brief));
}*/

fn read_json_from_file(mut path: String) -> FilterJson {
    if path.is_empty() {
        path = "src/filters.json".to_string();
    }
    let json_to_string = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str::<FilterJson>(&json_to_string).unwrap()
}

fn charge_environment_variables() -> EnvVariables {
    EnvVariables {
        local_port: dotenv::var("AGENT_PORT").unwrap(),
        remote_port: dotenv::var("NB_PORT").unwrap(),
        remote_addr: dotenv::var("NB_HOST").unwrap(),
        bind_addr: dotenv::var("AGENT_BIND_ADDR").unwrap(),
        filters: dotenv::var("FILE_AND_PATH").unwrap(),
        debug: if dotenv::var("DEBUG").unwrap().is_empty() {
            false
        } else {
            dotenv::var("DEBUG").unwrap().parse().unwrap()
        },
        mqtt: if dotenv::var("MQTT").unwrap().is_empty() {
            false
        } else {
            dotenv::var("MQTT").unwrap().parse().unwrap()
        },
    }
}

fn charge_mqtt_variables() -> MqttVariables {
    MqttVariables {
        broker_url: dotenv::var("BROKER_URL").unwrap(),
        broker_port: dotenv::var("BROKER_PORT").unwrap(),
        broker_auth_name: dotenv::var("BROKER_AUTH_USERNAME").unwrap(),
        broker_auth_password: dotenv::var("BROKER_AUTH_PASSWORD").unwrap(),
        broker_topic: dotenv::var("BROKER_TOPIC").unwrap(),
    }
}

fn initialize_mqtt(url: &String, port: u16, topic: &String) -> Client {
    let mqtt_options = MqttOptions::new("elegant_client", url, port);
    let (mut mqtt_client, mut connection) = Client::new(mqtt_options, 10);
    mqtt_client.subscribe(topic, QoS::AtLeastOnce).unwrap();
    thread::spawn(move || {
        for notification in connection.iter().enumerate() {
            println!("{:?}", notification);
        }
    });
    return mqtt_client;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let env_variables = charge_environment_variables();
    let mqtt_variables = charge_mqtt_variables();
    let mut mqtt_client: Option<Client> = None;
    if env_variables.mqtt == true {
        mqtt_client = Some(initialize_mqtt(
            &mqtt_variables.broker_url,
            mqtt_variables.broker_port.parse().unwrap(),
            &mqtt_variables.broker_topic,
        ));
    }
    let path = env_variables.filters;
    let filters: FilterJson = read_json_from_file((path).to_string());

    unsafe {
        DEBUG = env_variables.debug;
    }

    let local_port: i32 = env_variables.local_port.parse().unwrap();
    let remote_port: u16 = env_variables.remote_port.parse().unwrap();
    let remote_host: String = env_variables.remote_addr.parse().unwrap();
    let bind_addr: String = if env_variables.bind_addr.is_empty() {
        "127.0.0.1".to_owned()
    } else {
        env_variables.bind_addr.parse().unwrap()
    };

    let mut start_addrs: Vec<u32> = vec![];
    let mut end_addrs: Vec<u32> = vec![];

    if !filters.dev_addr_intervals.is_empty() {
        for intervals in &filters.dev_addr_intervals {
            if !intervals.dev_addr_end.is_empty() && !intervals.dev_addr_start.is_empty() {
                start_addrs
                    .push(u32::from_str_radix(intervals.dev_addr_start.as_str(), 16).unwrap());
                end_addrs.push(u32::from_str_radix(intervals.dev_addr_end.as_str(), 16).unwrap())
            } else {
                start_addrs.push(u32::from_str_radix("00000000", 16).unwrap());
                end_addrs.push(u32::from_str_radix("FFFFFFFF", 16).unwrap())
            }
        }
    }

    let mut dev_addr_list: Vec<u32> = vec![];
    if !filters.dev_addr.is_empty() {
        for dev_addr in &filters.dev_addr {
            dev_addr_list.push(u32::from_str_radix(dev_addr.as_str(), 16).unwrap());
        }
    }

    let mut start_deveui: Vec<u64> = vec![];
    let mut end_deveui: Vec<u64> = vec![];
    if !filters.dev_eui_intervals.is_empty() {
        for intervals in &filters.dev_eui_intervals {
            if !intervals.dev_eui_start.is_empty() && !intervals.dev_eui_end.is_empty() {
                start_deveui
                    .push(u64::from_str_radix(intervals.dev_eui_start.as_str(), 16).unwrap());
                end_deveui.push(u64::from_str_radix(intervals.dev_eui_end.as_str(), 16).unwrap())
            } else {
                start_deveui.push(u64::from_str_radix("0007ED0000000000", 16).unwrap());
                end_deveui.push(u64::from_str_radix("0007ED0000000FFF", 16).unwrap())
            }
        }
    }

    let fwinfo: ForwardInfo = ForwardInfo {
        dev_addrs: dev_addr_list,
        end_addr: end_addrs,
        start_addr: start_addrs,
        forward_host: &remote_host,
        start_filter_deveui: start_deveui,
        end_filter_deveui: end_deveui,
        port: remote_port,
        ..Default::default()
    };
    for ele in &fwinfo.start_addr {
        println!(
            "Allowing Dev addresses from {:x?} to {:x?}",
            fwinfo.start_addr[fwinfo.start_addr.iter().position(|&x| &x == ele).unwrap()],
            fwinfo.end_addr[fwinfo.start_addr.iter().position(|&x| &x == ele).unwrap()]
        );
    }
    // zmq::init_zmq();
    print!("List of allowed Device Address : ");
    for ele in &fwinfo.dev_addrs {
        print!("{:x} ", ele);
    }

    println!();
    for ele in &fwinfo.start_filter_deveui {
        println!(
            "Blocking Dev Eui from {:x?} to {:x?}",
            fwinfo.start_filter_deveui[fwinfo
                .start_filter_deveui
                .iter()
                .position(|&x| &x == ele)
                .unwrap()],
            fwinfo.end_filter_deveui[fwinfo
                .start_filter_deveui
                .iter()
                .position(|&x| &x == ele)
                .unwrap()]
        );
    }

    forward(
        &bind_addr,
        local_port,
        &remote_host,
        remote_port,
        fwinfo,
        mqtt_client,
        mqtt_variables.broker_topic,
    )
    .await?;
    Ok(())
}

fn debug(msg: String) {
    if false {
        println!("{}", msg);
    }
}

fn info(msg: String) {
    if true {
        println!("\nINFO: {}\n", msg);
    }
}

fn extract_dev_addr_array(v: Vec<u8>) -> [u8; 4] {
    let default_array: [u8; 4] = [0, 0, 0, 0];
    v.try_into().unwrap_or(default_array)
}

fn extract_dev_eui_array(v: Vec<u8>) -> [u8; 8] {
    let default_array: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    v.try_into().unwrap_or(default_array)
}

fn check_range<T: Display + PartialEq + PartialOrd>(
    dev: T,
    start_intervals: Vec<T>,
    end_intervals: Vec<T>,
) -> bool {
    let mut check: bool = false;
    for ele in &start_intervals {
        if dev >= start_intervals[start_intervals.iter().position(|x| x == ele).unwrap()]
            && dev <= end_intervals[start_intervals.iter().position(|x| x == ele).unwrap()]
        {
            check = true;
            break;
        }
    }
    return check;
}

fn send_to_broker(mqtt_client: Option<Client>, topic: String, json: String) {
    thread::spawn(move || {
        mqtt_client
            .unwrap()
            .publish(topic, QoS::AtLeastOnce, false, json.as_bytes())
            .unwrap();
    });
}

fn process_temperature(temperature: i8) -> bool {
    unsafe { E2FRAME_DATA.push(temperature) };
    if unsafe { E2FRAME_DATA.len() } >= E2FRAME_DATA_MAX_SIZE {
        return true;
    }
    return false;
}

async fn forward(
    bind_addr: &str,
    local_port: i32,
    remote_host: &str,
    remote_port: u16,
    fwinfo: ForwardInfo<'_>,
    mqtt_client: Option<Client>,
    topic: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // GET IP ADDRESS
    let gw_rpc_endpoint_address = local_ip_address::local_ip().unwrap().to_string();
    let gw_rpc_endpoint_port = format!("50051");

    // INIT RPC CLIENT
    let rpc_remote_host = "192.168.1.160";
    let rpc_remote_port = "50051";
    let mut rpc_client =
        init_rpc_client(rpc_remote_host.to_owned(), rpc_remote_port.to_owned()).await?;

    // Compute private ECC key
    let private_key: P256SecretKey<p256::NistP256> = P256SecretKey::random(&mut OsRng);
    let public_key: P256PublicKey<p256::NistP256> = private_key.public_key();
    // Get sec1 bytes of Public Key (TO SEND TO AS)
    let public_key_sec1_bytes = public_key.to_sec1_bytes();

    let request = tonic::Request::new(E2gwPubInfo {
        gw_ip_addr: gw_rpc_endpoint_address,
        gw_port: gw_rpc_endpoint_port,
        e2gw_pub_key: public_key_sec1_bytes.into_vec(),
    });
    let response = rpc_client.store_e2gw_pub_info(request).await?;

    let status_code = response.get_ref().status_code;
    if status_code < 200 || status_code > 299 {
        return Err("Unable to store public key".into());
    }
    let as_pub_key_sec1_bytes = response.get_ref().message.clone();
    let as_pub_key: P256PublicKey<p256::NistP256> =
        P256PublicKey::from_sec1_bytes(&as_pub_key_sec1_bytes).unwrap();

    let shared_secret =
        p256::ecdh::diffie_hellman(private_key.to_nonzero_scalar(), as_pub_key.as_affine());
    // Ok(rpc_client);
    info(format!(
        "Shared secret: {:?}",
        shared_secret.raw_secret_bytes()
    ));

    let local_addr = format!("{}:{}", bind_addr, local_port);
    let local = UdpSocket::bind(&local_addr).expect(&format!("Unable to bind to {}", &local_addr));
    let mut idx: u64 = 0;
    info(format!("Listening on {}", local.local_addr().unwrap()));
    info(format!("Forwarding to {}:{}", remote_host, remote_port));

    let remote_addr = format!("{}:{}", remote_host, remote_port);

    let responder = local.try_clone().expect(&format!(
        "Failed to clone primary listening address socket {}",
        local.local_addr().unwrap()
    ));
    let (main_sender, main_receiver) = channel::<(_, Vec<u8>)>();
    thread::spawn(move || {
        debug(format!(
            "Started new thread to deal out responses to clients"
        ));
        loop {
            let (dest, buf) = main_receiver.recv().unwrap();
            let to_send = buf.as_slice();
            responder.send_to(to_send, dest).expect(&format!(
                "Failed to forward response from upstream server to client {}",
                dest
            ));
        }
    });

    let mut client_map = HashMap::new();
    let mut buf = [0; 64 * 1024];

    loop {
        let (num_bytes, src_addr) = local.recv_from(&mut buf).expect("Didn't receive data");

        //we create a new thread for each unique client
        let mut remove_existing = false;
        loop {
            debug(format!("Received packet from client {}", src_addr));

            let mut ignore_failure = true;
            let client_id = format!("{}", src_addr);

            if remove_existing {
                debug(format!("Removing existing forwarder from map."));
                client_map.remove(&client_id);
            }

            let sender = client_map.entry(client_id.clone()).or_insert_with(|| {
                //we are creating a new listener now, so a failure to send shoud be treated as an error
                ignore_failure = false;

                let local_send_queue = main_sender.clone();
                let (sender, receiver) = channel::<Vec<u8>>();
                let remote_addr_copy = remote_addr.clone();
                thread::spawn(move || {
                    let mut rng = rand::thread_rng();

                    //regardless of which port we are listening to, we don't know which interface or IP
                    //address the remote server is reachable via, so we bind the outgoing
                    //connection to 0.0.0.0 in all cases.
                    let temp_outgoing_addr = format!("0.0.0.0:{}", rng.gen_range(50000, 59999));
                    debug(format!("Establishing new forwarder for client {} on {}", src_addr, &temp_outgoing_addr));
                    let upstream_send = UdpSocket::bind(&temp_outgoing_addr)
                        .expect(&format!("Failed to bind to transient address {}", &temp_outgoing_addr));
                    let upstream_recv = upstream_send.try_clone()
                        .expect("Failed to clone client-specific connection to upstream!");

                    let mut timeouts: u64 = 0;
                    let timed_out = Arc::new(AtomicBool::new(false));

                    let local_timed_out = timed_out.clone();


                    thread::spawn(move || {
                        let mut from_upstream = [0; 64 * 1024];

                        upstream_recv.set_read_timeout(Some(Duration::from_millis(TIMEOUT + 100))).unwrap();
                        loop {
                            match upstream_recv.recv_from(&mut from_upstream) {
                                Ok((bytes_rcvd, _)) => {
                                    let to_send = from_upstream[..bytes_rcvd].to_vec();
                                    println!("Forwarding packet from client {} to upstream server", PACKETNAMES[&to_send[3]]);

                                    local_send_queue.send((src_addr, to_send))
                                        .expect("Failed to queue response from upstream server for forwarding!");
                                }
                                Err(_) => {
                                    if local_timed_out.load(Ordering::Relaxed) {
                                        debug(format!("Terminating forwarder thread for client {} due to timeout", src_addr));
                                        break;
                                    }
                                }
                            };
                        }
                    });

                    loop {
                        match receiver.recv_timeout(Duration::from_millis(TIMEOUT)) {
                            Ok(from_client) => {
                                println!("Forwarding packet from client {} to upstream server", PACKETNAMES[&from_client[3]]);
                                upstream_send.send_to(from_client.as_slice(), &remote_addr_copy)
                                    .expect(&format!("Failed to forward packet from client {} to upstream server!", src_addr));
                                timeouts = 0; //reset timeout count
                            }
                            Err(_) => {
                                timeouts += 1;
                                if timeouts >= 10 {
                                    debug(format!("Disconnecting forwarder for client {} due to timeout", src_addr));
                                    timed_out.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }
                        };
                    }
                });
                sender
            });

            let to_send = buf[..num_bytes].to_vec();

            let mut will_send = true;
            let mut edge_send = false;
            match &to_send[3] {
                // Scritto da Copilot: Match a single value to a single value to avoid a match on a slice of a single value and a single value slice. This is a bit of a hack, but it works. I'm sorry. I'm sorry. I'm sorry.
                0 => {
                    // PUSH_DATA
                    let data_json: Rxpk = get_data_from_json(&to_send[12..]);
                    debug(format!(
                        "Evaluate if forwarding packet from client {:?} to upstream server",
                        data_json.rxpk
                    ));
                    if data_json.rxpk.len() == 0 {
                        match fwinfo.forward_protocol {
                            ForwardProtocols::UDP => {
                                debug(format!(
                                    "Forwarding Other data to {:x?}",
                                    fwinfo.forward_host
                                ));
                            } // _ => panic!("Forwarding protocol not implemented!"),
                        }
                    } else {
                        for packet in data_json.rxpk.iter() {
                            let data: Vec<u8> = base64::decode(&packet.data).unwrap();
                            let data1: Vec<u8> = base64::decode(&packet.data).unwrap();
                            let data2: Vec<u8> = base64::decode(&packet.data).unwrap();

                            let gwmac: String = hex::encode(&to_send[4..12]);
                            debug(format!("Extracted GwMac {:x?}", gwmac));

                            if let Ok(PhyPayload::Data(DataPayload::Encrypted(phy))) = parse(data) {
                                let fhdr = phy.fhdr();
                                let fcnt = fhdr.fcnt();
                                let dev_addr_vec = fhdr.dev_addr().as_ref().to_vec();

                                let dev_addr = u32::from_be_bytes(extract_dev_addr_array(
                                    dev_addr_vec.into_iter().rev().collect(),
                                ));
                                debug(format!("Extracted DevAddr {:x?}", dev_addr));
                                if mqtt_client.clone().is_some() {
                                    let json_to_send = build_json_for_broker(
                                        idx,
                                        gwmac,
                                        packet,
                                        Some(fcnt),
                                        phy.mhdr().mtype(),
                                        Option::from(dev_addr),
                                        None,
                                    );
                                    idx = (idx + 1) % 18446744073709551615;
                                    debug(format!("Payload Prepared for broker {}", json_to_send));
                                    send_to_broker(
                                        mqtt_client.clone(),
                                        topic.clone(),
                                        json_to_send,
                                    );
                                };
                                if check_range(
                                    dev_addr,
                                    fwinfo.start_addr.clone(),
                                    fwinfo.end_addr.clone(),
                                ) || fwinfo.dev_addrs.contains(&dev_addr)
                                {
                                    match dev_addr {
                                        0x001AED84 => {
                                            let app_s_key: AES128 = AES128::from([
                                                0x03, 0x8A, 0xBE, 0xDC, 0x09, 0xB2, 0x68, 0xE8,
                                                0xE9, 0xC3, 0x5B, 0xF1, 0x5F, 0xDE, 0x71, 0xE9,
                                            ]);
                                            let decrypted_data_payload = phy
                                                .decrypt(
                                                    Some(&app_s_key),
                                                    Some(&app_s_key),
                                                    fcnt.into(),
                                                )
                                                .unwrap();
                                            debug(format!("Decrypted Packet"));
                                            let frame_payload_result =
                                                decrypted_data_payload.frm_payload().unwrap();
                                            match frame_payload_result {
                                                lorawan_encoding::parser::FRMPayload::Data(
                                                    frame_payload,
                                                ) => {
                                                    if frame_payload.len() > 0 {
                                                        let temperature: i8 =
                                                            frame_payload[0].try_into().unwrap();
                                                        info(format!(
                                                            "TEMPERATURE: {:?}",
                                                            temperature
                                                        ));
                                                        edge_send =
                                                            process_temperature(temperature);
                                                        will_send = false;
                                                    }
                                                }
                                                _ => info(format!("NO BENE")),
                                            };
                                        }
                                        _ => {
                                            match fwinfo.forward_protocol {
                                                ForwardProtocols::UDP => {
                                                    debug(format!(
                                                        "Forwarding to {:x?}",
                                                        fwinfo.forward_host
                                                    ));
                                                } // _ => panic!("Forwarding protocol not implemented!"),
                                            }
                                        }
                                    }
                                } else {
                                    debug(format!(
                                        "Not forwarding packet from client {} to upstream server",
                                        PACKETNAMES[&to_send[3]]
                                    ));
                                    will_send = false;
                                    break;
                                }
                            } else if let Ok(PhyPayload::JoinRequest(phy)) = parse(data1) {
                                let dev_eui_vec = phy.dev_eui().as_ref().to_vec();
                                let dev_eui = u64::from_be_bytes(extract_dev_eui_array(
                                    dev_eui_vec.into_iter().rev().collect(),
                                ));
                                debug(format!("Extracted DevEui {:x?}", dev_eui));
                                if mqtt_client.clone().is_some() {
                                    let json_to_send = build_json_for_broker(
                                        idx,
                                        gwmac,
                                        packet,
                                        None,
                                        phy.mhdr().mtype(),
                                        None,
                                        Some(dev_eui),
                                    );
                                    idx = (idx + 1) % 18446744073709551615;
                                    debug(format!("Payload Prepared for broker {}", json_to_send));
                                    send_to_broker(
                                        mqtt_client.clone(),
                                        topic.clone(),
                                        json_to_send,
                                    );
                                };
                                if !check_range(
                                    dev_eui,
                                    fwinfo.start_filter_deveui.clone(),
                                    fwinfo.end_filter_deveui.clone(),
                                ) {
                                    match fwinfo.forward_protocol {
                                        ForwardProtocols::UDP => {
                                            debug(format!(
                                                "Forwarding to {:x?}  JoinRequest with len {}",
                                                fwinfo.forward_host,
                                                phy.as_bytes().len()
                                            ));
                                        } // _ => panic!("Forwarding protocol not implemented!"),
                                    }
                                } else {
                                    debug(format!(
                                        "Not forwarding packet from client {} to upstream server",
                                        PACKETNAMES[&to_send[3]]
                                    ));
                                    will_send = false;
                                    break;
                                }
                            } else {
                                debug(format!("Not forwarding packet from client {} to upstream server, Unknown Packet with size {}, data: {:x?}", PACKETNAMES[&to_send[3]], data2.len(), data2));
                                will_send = false;
                                break;
                                // match fwinfo.forward_protocol {
                                //     ForwardProtocols::UDP => {
                                //         debug(format!("Forwarding UnknownData data to {:x?}, size: {}", fwinfo.forward_host, phy.as_bytes().len()));
                                //     }
                                //     // _ => panic!("Forwarding protocol not implemented!"),
                                // }
                            }
                        }
                    }
                }
                _ => (),
            }

            if edge_send {
                let mut temp_sum: i32 = 0;
                let mut array_str = format!("[");
                for temp in unsafe { E2FRAME_DATA.iter() } {
                    temp_sum += i32::from(*temp);
                    array_str += &format!("{}, ", temp);
                }
                array_str += "]";
                let temp_avg: i32 = temp_sum / unsafe { E2FRAME_DATA.len() } as i32;

                info(format!(
                    "Average Temp to Send: {}, from {}",
                    temp_avg, array_str
                ));
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");

                let request = tonic::Request::new(NewDataRequest {
                    name: "Hello, World!".into(),
                    timetag: since_the_epoch.as_millis() as u64,
                });
                println!("Sending request: {:?}", request);
                let response = rpc_client.new_data(request).await?;

                println!("RESPONSE={:?}", response);

                // Clean up E2DATA_FRAME
                unsafe { E2FRAME_DATA = vec![] };
            }
            if will_send {
                match sender.send(to_send.to_vec().clone()) {
                    Ok(_) => {
                        println!(
                            "Forwarding {} ({}) to upstream server",
                            PACKETNAMES[&to_send[3]], &to_send[3]
                        );

                        break;
                    }
                    Err(_) => {
                        if !ignore_failure {
                            panic!(
                                "Failed to send message to datagram forwarder for client {}",
                                client_id
                            );
                        }
                        //client previously timed out
                        debug(format!(
                            "New connection received from previously timed-out client {}",
                            client_id
                        ));
                        remove_existing = true;
                        continue;
                    }
                }
            } else {
                break;
            }
        }
    }
}
