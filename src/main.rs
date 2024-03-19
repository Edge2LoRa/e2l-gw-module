mod e2gw_rpc_client;
mod e2gw_rpc_server;
mod e2l_crypto;
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

use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::FcntStruct;
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::GwFrameStats;
// use e2l_crypto::e2l_crypto::e2l_crypto::ProcessedFrameResult;
use mqtt_client::mqtt_structs::mqtt_structs::MqttVariables;
use sysinfo::{CpuExt, System, SystemExt};

// use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::EdgeData;
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::GwLog;
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::SysLog;
// E2L
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::init_rpc_client;
use e2gw_rpc_client::e2gw_rpc_client::e2gw_rpc_client::E2gwPubInfo;

use e2gw_rpc_server::e2gw_rpc_server::e2gw_rpc_server::edge2_gateway_server::Edge2GatewayServer;
use e2gw_rpc_server::e2gw_rpc_server::e2gw_rpc_server::MyEdge2GatewayServer;
use tonic::transport::Server;

use json_structs::filters_json_structs::filter_json::{EnvVariables, FilterJson};
use lorawan_encoding::parser::{parse, AsPhyPayloadBytes, DataHeader, DataPayload, PhyPayload};
use lorawan_structs::lorawan_structs::lora_structs::Rxpk;
use lorawan_structs::lorawan_structs::{ForwardInfo, ForwardProtocols};
use rand::Rng;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::format;
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

// E2L modules
use paho_mqtt as mqtt;

use e2l_crypto::e2l_crypto::E2L_CRYPTO;
static EDGE_FRAME_ID: u64 = 1;
static LEGACY_FRAME_ID: u64 = 2;
static EDGE_FRAME_ID_NOT_PROCESSED: u64 = 3;

static DEFAULT_APP_PORT: u8 = 2;
static _DEFAULT_E2L_JOIN_PORT: u8 = 3;
static DEFAULT_E2L_APP_PORT: u8 = 4;
static _DEFAULT_E2L_COMMAND_PORT: u8 = 5;

static mut LEGACY_FRAMES_NUM: u64 = 0;
static mut LEGACY_FRAMES_LAST: u64 = 0;
static mut LEGACY_FRAMES_FCNTS: Vec<FcntStruct> = Vec::new();
static mut EDGE_FRAMES_NUM: u64 = 0;
static mut EDGE_FRAMES_LAST: u64 = 0;
static mut EDGE_FRAMES_FCNTS: Vec<FcntStruct> = Vec::new();
static mut EDGE_NOT_PROCESSED_FRAMES_NUM: u64 = 0;
static mut EDGE_NOT_PROCESSED_FRAMES_LAST: u64 = 0;
static mut EDGE_NOT_PROCESSED_FRAMES_FCNTS: Vec<FcntStruct> = Vec::new();

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
    }
}

fn charge_mqtt_variables() -> MqttVariables {
    MqttVariables {
        broker_url: dotenv::var("BROKER_URL").unwrap(),
        broker_port: dotenv::var("BROKER_PORT").unwrap(),
        broker_auth_name: dotenv::var("BROKER_AUTH_USERNAME").unwrap(),
        broker_auth_password: dotenv::var("BROKER_AUTH_PASSWORD").unwrap(),
        broker_topic: dotenv::var("BROKER_TOPIC").unwrap(),
        broker_qos: dotenv::var("BROKER_QOS").unwrap().parse::<i32>().unwrap(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let env_variables = charge_environment_variables();

    // INIT MQTT CLIENT
    info(format!("Init MQTT client & connect to broker..."));
    let mqtt_variables = charge_mqtt_variables();
    let mqtt_client: mqtt::AsyncClient = mqtt::AsyncClient::new(format!(
        "{}:{}",
        mqtt_variables.broker_url.clone(),
        mqtt_variables.broker_port.clone()
    ))
    .unwrap_or_else(|err| {
        println!("Error creating the client: {:?}", err);
        std::process::exit(1);
    });
    let mut mqtt_conn_opts_builder = mqtt::ConnectOptionsBuilder::new();
    mqtt_conn_opts_builder.user_name(mqtt_variables.broker_auth_name.clone());
    mqtt_conn_opts_builder.password(mqtt_variables.broker_auth_password.clone());
    // Connect and wait for it to complete or fail
    if let Err(e) = mqtt_client
        .connect(mqtt_conn_opts_builder.finalize())
        .wait()
    {
        println!("Unable to connect: {:?}", e);
        std::process::exit(1);
    }
    info(format!("MQTT INIT AND CONNECT COMPLETED!"));

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
        mqtt_variables,
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
        //         println!("\nINFO: {}\n", msg);
        println!("INFO: {}", msg);
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

async fn forward(
    bind_addr: &str,
    local_port: i32,
    remote_host: &str,
    remote_port: u16,
    fwinfo: ForwardInfo<'_>,
    mqtt_client: mqtt::AsyncClient,
    mqtt_variables: MqttVariables,
) -> Result<(), Box<dyn std::error::Error>> {
    // GET IGNORE LOG FLAG
    let ignore_logs_str_flag = dotenv::var("IGNORE_LOGS").unwrap();
    let ignore_logs_flag: bool;
    if ignore_logs_str_flag == "1" {
        ignore_logs_flag = true;
    } else {
        ignore_logs_flag = false;
    }

    // GET IP ADDRESS
    let gw_rpc_endpoint_address = local_ip_address::local_ip().unwrap().to_string();
    let gw_sys_rpc_endpoint_address = local_ip_address::local_ip().unwrap().to_string();
    let gw_frames_rpc_endpoint_address = local_ip_address::local_ip().unwrap().to_string();
    let gw_rpc_endpoint_port = dotenv::var("GW_RPC_ENDPOINT_PORT").unwrap();
    let rpc_endpoint = format!("0.0.0.0:{}", gw_rpc_endpoint_port.clone());

    // CREATE MQTT TOPIC
    let mqtt_process_topic = mqtt::Topic::new(
        &mqtt_client,
        mqtt_variables.broker_topic,
        mqtt_variables.broker_qos,
    );
    // INIT RPC SERVER
    let rpc_server = MyEdge2GatewayServer {};
    let rt = tokio::runtime::Runtime::new().expect("Failed to obtain a new RunTime object");
    info(format!("Starting RPC Server on {}", rpc_endpoint.clone()));
    let servicer = Server::builder().add_service(Edge2GatewayServer::new(rpc_server));

    thread::spawn(move || {
        let server_future = servicer.serve(rpc_endpoint.parse().unwrap());
        rt.block_on(server_future)
            .expect("RPC Server failed to start");
    });

    // Compute private ECC key
    let compressed_public_key = unsafe { E2L_CRYPTO.generate_ecc_keys() };

    // INIT RPC CLIENT
    let rpc_remote_host = dotenv::var("RPC_DM_REMOTE_HOST").unwrap();
    let rpc_remote_port = dotenv::var("RPC_DM_REMOTE_PORT").unwrap();
    let mut rpc_client = init_rpc_client(rpc_remote_host.clone(), rpc_remote_port.clone()).await?;

    let request: tonic::Request<E2gwPubInfo> = tonic::Request::new(E2gwPubInfo {
        gw_ip_addr: gw_rpc_endpoint_address.clone(),
        gw_port: gw_rpc_endpoint_port.clone(),
        e2gw_pub_key: compressed_public_key.into_vec(),
    });
    let response = rpc_client.store_e2gw_pub_info(request).await?;
    let status_code = response.get_ref().status_code;
    if status_code < 200 || status_code > 299 {
        return Err("Unable to send public key to the AS".into());
    }

    let local_addr = format!("{}:{}", bind_addr, local_port);
    let local = UdpSocket::bind(&local_addr).expect(&format!("Unable to bind to {}", &local_addr));

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

    let mut rpc_client_sys =
        init_rpc_client(rpc_remote_host.clone(), rpc_remote_port.clone()).await?;
    let mut rpc_client_frames =
        init_rpc_client(rpc_remote_host.clone(), rpc_remote_port.clone()).await?;

    // Start sys monitoring thread
    let rt_sys =
        tokio::runtime::Runtime::new().expect("Failed to obtain a new RunTime object for SysLog");
    thread::spawn(move || {
        info(format!("Started new thread to get performance (CPU ; MEM)"));

        let mut s: System = System::new_all();

        loop {
            s.refresh_memory();
            let used_memory = s.used_memory();
            let available_memory = s.available_memory();
            debug(format!("{} bytes", used_memory));
            debug(format!("{} bytes", available_memory));

            s.refresh_cpu(); // Refreshing CPU information.
            let used_cpu = s.global_cpu_info().cpu_usage();
            debug(format!("{}%", used_cpu));

            /*
            // Network interfaces name, data received and data transmitted:
            println!("=> networks:");
            for (interface_name, data) in sys.networks() {
                println!("{}: {}/{} B", interface_name, data.received(), data.transmitted());
            }
            */

            let log_request: tonic::Request<SysLog> = tonic::Request::new(SysLog {
                gw_id: gw_sys_rpc_endpoint_address.clone(),
                memory_usage: used_memory,
                memory_available: available_memory,
                cpu_usage: used_cpu,
                data_received: 0,
                data_transmitted: 0,
            });
            debug(format!("{:?}", log_request));
            let response_sys = rpc_client_sys.sys_log(log_request);
            rt_sys
                .block_on(response_sys)
                .expect("RPC Server failed to start");

            thread::sleep(Duration::from_millis(5000));
        }
    });

    // Start frames counter thread
    let rt_frames_counter =
        tokio::runtime::Runtime::new().expect("Failed to obtain a new RunTime object for SysLog");
    thread::spawn(move || {
        info(format!("Starting frames counter stats thread"));
        loop {
            let gw_frame_stats_request: tonic::Request<GwFrameStats>;
            unsafe {
                let legacy_delta: u64 = LEGACY_FRAMES_NUM - LEGACY_FRAMES_LAST;
                LEGACY_FRAMES_LAST = LEGACY_FRAMES_NUM;
                let legacy_fcnts: Vec<FcntStruct> = LEGACY_FRAMES_FCNTS.clone();
                LEGACY_FRAMES_FCNTS = Vec::new();

                let edge_delta: u64 = EDGE_FRAMES_NUM - EDGE_FRAMES_LAST;
                EDGE_FRAMES_LAST = EDGE_FRAMES_NUM;
                let edge_fcnts: Vec<FcntStruct> = EDGE_FRAMES_FCNTS.clone();
                EDGE_FRAMES_FCNTS = Vec::new();

                let edge_not_processed_delta =
                    EDGE_NOT_PROCESSED_FRAMES_NUM - EDGE_NOT_PROCESSED_FRAMES_LAST;
                EDGE_NOT_PROCESSED_FRAMES_LAST = EDGE_NOT_PROCESSED_FRAMES_NUM;
                let edge_not_processed_fcnts: Vec<FcntStruct> =
                    EDGE_NOT_PROCESSED_FRAMES_FCNTS.clone();
                EDGE_NOT_PROCESSED_FRAMES_FCNTS = Vec::new();

                gw_frame_stats_request = tonic::Request::new(GwFrameStats {
                    gw_id: gw_frames_rpc_endpoint_address.clone(),
                    legacy_frames: legacy_delta,
                    legacy_fcnts: legacy_fcnts,
                    edge_frames: edge_delta,
                    edge_fcnts: edge_fcnts,
                    edge_not_processed_frames: edge_not_processed_delta,
                    edge_not_processed_fcnts: edge_not_processed_fcnts,
                });

                info(format!("Received Legacy Frame: {}", legacy_delta));
                info(format!("Received Edge Frame: {}", edge_delta));
                info(format!(
                    "Received Edge Frame not processed: {}",
                    edge_not_processed_delta
                ));
            }
            let response_frames = rpc_client_frames.gw_frames_stats(gw_frame_stats_request);
            rt_frames_counter
                .block_on(response_frames)
                .expect("RPC Server failed to start");
            thread::sleep(Duration::from_millis(5000));
        }
    });

    let mut client_map = HashMap::new();
    let mut buf = [0; 64 * 1024];

    info(format!("Starting Listening for incoming LoRaWAN packets!"));
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
                                    debug(format!("Forwarding packet from client {} to upstream server", PACKETNAMES[&to_send[3]]));

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
                                debug(format!("Forwarding packet from client {} to upstream server", PACKETNAMES[&from_client[3]]));
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

                            let gwmac: String = hex::encode(&to_send[4..12]);
                            debug(format!("Extracted GwMac {:x?}", gwmac));

                            let parsed_data = parse(data.clone());

                            match parsed_data {
                                Ok(PhyPayload::Data(DataPayload::Encrypted(phy))) => {
                                    let fhdr = phy.fhdr();
                                    let fcnt = fhdr.fcnt();
                                    let dev_addr_vec = fhdr.dev_addr().as_ref().to_vec();
                                    let aux: Vec<u8> =
                                        dev_addr_vec.clone().into_iter().rev().collect();
                                    let f_port = phy.f_port().unwrap();
                                    let strs: Vec<String> =
                                        aux.iter().map(|b| format!("{:02X}", b)).collect();
                                    let dev_addr_string = strs.join("");

                                    // let dev_addr_string = format!("{:x}", dev_addr_vec.clone());
                                    let dev_addr = u32::from_be_bytes(extract_dev_addr_array(
                                        dev_addr_vec.into_iter().rev().collect(),
                                    ));

                                    let is_active: bool;
                                    unsafe { is_active = E2L_CRYPTO.is_active }
                                    if is_active {
                                        // get epoch time
                                        let start = SystemTime::now();
                                        let timetag = start
                                            .duration_since(UNIX_EPOCH)
                                            .expect("Time went backwards");

                                        // Check if enabled E2ED
                                        let e2ed_enabled: bool;
                                        unsafe {
                                            e2ed_enabled = (f_port == DEFAULT_E2L_APP_PORT)
                                                && E2L_CRYPTO
                                                    .check_e2ed_enabled(dev_addr_string.clone());
                                        }

                                        if e2ed_enabled {
                                            let _tok: mqtt::DeliveryToken =
                                                mqtt_process_topic.publish("Hello, World!");

                                            // unsafe {
                                            // let ret: Option<ProcessedFrameResult> = E2L_CRYPTO
                                            //     .process_frame(
                                            //         dev_addr_string.clone(),
                                            //         fcnt,
                                            //         phy,
                                            //     );
                                            // if ret.is_some() {
                                            //     let processed_frame_result: ProcessedFrameResult = ret.unwrap();

                                            //     // SEND LOG
                                            //     if !ignore_logs_flag {
                                            //         let log_request: tonic::Request<GwLog> =
                                            //             tonic::Request::new(GwLog {
                                            //                 gw_id: gw_rpc_endpoint_address
                                            //                     .clone(),
                                            //                 dev_addr: dev_addr_string.clone(),
                                            //                 log: format!(
                                            //                     "Processed Edge Frame from {}",
                                            //                     dev_addr.clone()
                                            //                 ),
                                            //                 frame_type: EDGE_FRAME_ID,
                                            //                 fcnt: fcnt as u64,
                                            //                 timetag: processed_frame_result
                                            //                     .timetag,
                                            //             });
                                            //         rpc_client.gw_log(log_request).await?;
                                            //     }
                                            //     EDGE_FRAMES_NUM = EDGE_FRAMES_NUM + 1;
                                            //     EDGE_FRAMES_FCNTS.push(FcntStruct {
                                            //         dev_addr: dev_addr_string.clone(),
                                            //         fcnt: fcnt as u64,
                                            //     });

                                            //     // AGGREGATION RESULT
                                            //     if processed_frame_result
                                            //         .aggregation_option
                                            //         .is_some()
                                            //     {
                                            //         let ret = processed_frame_result
                                            //             .aggregation_option
                                            //             .unwrap();
                                            //         // get epoch time
                                            //         let start = SystemTime::now();
                                            //         let since_the_epoch = start
                                            //             .duration_since(UNIX_EPOCH)
                                            //             .expect("Time went backwards");
                                            //         let edge_data_request: tonic::Request<
                                            //             EdgeData,
                                            //         > = tonic::Request::new(EdgeData {
                                            //             gw_id: gw_rpc_endpoint_address.clone(),
                                            //             dev_eui: ret.dev_eui,
                                            //             dev_addr: ret.dev_addr,
                                            //             aggregated_data: ret.aggregated_data,
                                            //             fcnts: ret.fcnts as Vec<u64>,
                                            //             timetag: since_the_epoch.as_millis()
                                            //                 as u64,
                                            //         });
                                            //         let _response = rpc_client
                                            //             .new_data(edge_data_request)
                                            //             .await?;
                                            //     }
                                            // } else {
                                            //     debug(format!("Device not found or aggregation function not defined!"));
                                            // }
                                            // }
                                            will_send = false;
                                        } else {
                                            match fwinfo.forward_protocol {
                                                ForwardProtocols::UDP => {
                                                    debug(format!(
                                                        "Forwarding to {:x?}",
                                                        fwinfo.forward_host
                                                    ));

                                                    if f_port == DEFAULT_APP_PORT {
                                                        debug(format!(
                                                            "Forwarding Legacy Frame to {}",
                                                            dev_addr.clone()
                                                        ));

                                                        if !ignore_logs_flag {
                                                            let log_request: tonic::Request<GwLog> =
                                                            tonic::Request::new(GwLog {
                                                                gw_id: gw_rpc_endpoint_address
                                                                    .clone(),
                                                                dev_addr: dev_addr_string.clone(),
                                                                log: format!("Received Legacy Frame from {}", dev_addr.clone()),
                                                                frame_type: LEGACY_FRAME_ID,
                                                                fcnt: fcnt as u64,
                                                                timetag: timetag.as_millis() as u64,
                                                            });
                                                            rpc_client.gw_log(log_request).await?;
                                                        }
                                                        unsafe {
                                                            LEGACY_FRAMES_NUM =
                                                                LEGACY_FRAMES_NUM + 1;
                                                            LEGACY_FRAMES_FCNTS.push(FcntStruct {
                                                                dev_addr: dev_addr_string.clone(),
                                                                fcnt: fcnt as u64,
                                                            });
                                                        }
                                                    } else {
                                                        if f_port == DEFAULT_E2L_APP_PORT {
                                                            // SEND LOG
                                                            if !ignore_logs_flag {
                                                                let log_request: tonic::Request<GwLog> = tonic::Request::new(GwLog {
                                                                gw_id: gw_rpc_endpoint_address.clone(),
                                                                dev_addr: dev_addr_string.clone(),
                                                                log: format!(
                                                                    "Received Edge Frame from {} (NOT PROCESSING)",
                                                                    dev_addr.clone()
                                                                ),
                                                                frame_type: EDGE_FRAME_ID_NOT_PROCESSED,
                                                                fcnt: fcnt as u64,
                                                                timetag: timetag.as_millis() as u64,
                                                                });
                                                                rpc_client
                                                                    .gw_log(log_request)
                                                                    .await?;
                                                            }
                                                            unsafe {
                                                                EDGE_NOT_PROCESSED_FRAMES_NUM =
                                                                    EDGE_NOT_PROCESSED_FRAMES_NUM
                                                                        + 1;
                                                                EDGE_NOT_PROCESSED_FRAMES_FCNTS
                                                                    .push(FcntStruct {
                                                                        dev_addr: dev_addr_string
                                                                            .clone(),
                                                                        fcnt: fcnt as u64,
                                                                    });
                                                            }
                                                        }
                                                    }
                                                } // _ => panic!("Forwarding protocol not implemented!"),
                                            }
                                        }
                                    } else {
                                        debug(format!("Not forwarding packet from client {} to upstream server", PACKETNAMES[&to_send[3]]));
                                        will_send = false;
                                        break;
                                    }
                                }
                                Ok(PhyPayload::JoinRequest(phy)) => {
                                    let dev_eui_vec = phy.dev_eui().as_ref().to_vec();
                                    let dev_eui = u64::from_be_bytes(extract_dev_eui_array(
                                        dev_eui_vec.into_iter().rev().collect(),
                                    ));
                                    debug(format!("Extracted DevEui {:x?}", dev_eui));
                                    if true
                                        || !check_range(
                                            dev_eui,
                                            fwinfo.start_filter_deveui.clone(),
                                            fwinfo.end_filter_deveui.clone(),
                                        )
                                    {
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
                                }
                                Ok(_) => {}
                                Err(_) => {
                                    debug(format!("Not forwarding packet from client {} to upstream server, Unknown Packet with size {}, data: {:x?}", PACKETNAMES[&to_send[3]], data.len(), data));
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
                }
                _ => (),
            }

            if will_send {
                match sender.send(to_send.to_vec().clone()) {
                    Ok(_) => {
                        debug(format!(
                            "Forwarding {} ({}) to upstream server",
                            PACKETNAMES[&to_send[3]], &to_send[3]
                        ));

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
