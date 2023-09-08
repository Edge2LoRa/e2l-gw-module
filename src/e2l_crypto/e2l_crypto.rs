use self::e2l_crypto::E2LCrypto;
pub(crate) mod e2l_crypto {
    // Crypto
    extern crate p256;

    use lorawan_encoding::default_crypto::DefaultFactory;
    use lorawan_encoding::keys::AES128;
    use lorawan_encoding::parser::EncryptedDataPayload;
    use p256::elliptic_curve::ecdh::SharedSecret as P256SharedSecret;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::elliptic_curve::PublicKey as P256PublicKey;
    use p256::elliptic_curve::SecretKey as P256SecretKey;
    use sha256::digest;

    pub struct DevInfo {
        dev_eui: String,
        dev_addr: String,
        dev_public_key: P256PublicKey<p256::NistP256>,
        edge_s_enc_key: AES128,
        edge_s_int_key: AES128,
    }

    #[derive(Default)]
    pub struct E2LCrypto {
        pub private_key: Option<P256SecretKey<p256::NistP256>>,
        pub public_key: Option<P256PublicKey<p256::NistP256>>,
        pub compressed_public_key: Option<Box<[u8]>>,
        pub active_directory: Vec<DevInfo>,
    }

    impl E2LCrypto {
        /*
           @brief: This function computes the private/public ecc key pair of the GW
           @return: the compressed public key of the GW to be sent to the AS
        */
        pub fn generate_ecc_keys(&mut self) -> Box<[u8]> {
            self.private_key = Some(P256SecretKey::random(&mut OsRng));
            self.public_key = Some(self.private_key.clone().unwrap().public_key());
            // Get sec1 bytes of Public Key (TO SEND TO AS)
            self.compressed_public_key = Some(self.public_key.clone().unwrap().to_sec1_bytes());
            return self.compressed_public_key.clone().unwrap();
        }
        /*
           @brief: This function stores the public info of a dev and computes the g_gw_ed to send to the AS
           @param dev_eui: the dev_eui of the device
           @param dev_addr: the dev_addr of the device
           @param g_as_ed_compressed: the compressed g_as_ed computed by the AS
           @param dev_public_key_compressed: the compressed public key of the device
           @return: the g_gw_ed to send to the AS
        */

        pub fn handle_ed_pub_info(
            &mut self,
            dev_eui: String,
            dev_addr: String,
            g_as_ed_compressed: Vec<u8>,
            dev_public_key_compressed: Vec<u8>,
        ) -> Vec<u8> {
            // GET g_as_ed
            let aa: [u8; 32] = g_as_ed_compressed.try_into().unwrap();
            let test_private: P256SecretKey<p256::NistP256> =
                P256SecretKey::from_bytes(&aa.into()).unwrap();
            let g_as_ed = test_private.public_key();

            // Get Device public key
            let dev_public_key_result: Result<
                P256PublicKey<p256::NistP256>,
                p256::elliptic_curve::Error,
            > = P256PublicKey::from_sec1_bytes(&dev_public_key_compressed);
            let dev_public_key: P256PublicKey<p256::NistP256>;
            match dev_public_key_result {
                Ok(x) => {
                    dev_public_key = x;
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                    return vec![];
                }
            };

            // Compute the Edge Session Key
            let edge_s_key: P256SharedSecret<p256::NistP256> = p256::ecdh::diffie_hellman(
                self.private_key.clone().unwrap().to_nonzero_scalar(),
                g_as_ed.as_affine(),
            );
            println!("\nEdgeSKey: {:?}\n", edge_s_key.raw_secret_bytes());
            let edge_s_key_bytes: Vec<u8> = edge_s_key.raw_secret_bytes().to_vec();

            // Compute Edge Session Integrity Key
            let mut edge_s_key_int_bytes_before_hash = edge_s_key_bytes.clone();
            edge_s_key_int_bytes_before_hash.insert(0, 1);
            let binding = digest(edge_s_key_int_bytes_before_hash);
            let edge_s_key_int_hash = binding.as_bytes();
            let edge_s_key_int_bytes: [u8; 16] = (&edge_s_key_int_hash[0..16]).try_into().unwrap();
            let edge_s_int_key = AES128::from(edge_s_key_int_bytes);
            println!("\nEdgeSIntKey: {:?}\n", edge_s_int_key);

            // Compute Edge Session Encryption Key
            let mut edge_s_enc_key_bytes_before_hash = edge_s_key_bytes.clone();
            edge_s_enc_key_bytes_before_hash.insert(0, 0);
            let binding = digest(edge_s_enc_key_bytes_before_hash);
            let edge_s_enc_key_hash = binding.as_bytes();
            let edge_s_enc_key_bytes: [u8; 16] = (&edge_s_enc_key_hash[0..16]).try_into().unwrap();
            let edge_s_enc_key = AES128::from(edge_s_enc_key_bytes);
            println!("\nEdgeSEncKey: {:?}\n", edge_s_enc_key);

            let mut dev_info_found = false;
            for dev_info in self.active_directory.iter_mut() {
                if dev_info.dev_addr == dev_addr {
                    dev_info.dev_public_key = dev_public_key.clone();
                    dev_info.edge_s_enc_key = edge_s_enc_key;
                    dev_info.edge_s_int_key = edge_s_int_key;
                    dev_info_found = true;
                    break;
                }
            }
            if !dev_info_found {
                let new_dev_info: DevInfo = DevInfo {
                    dev_eui: dev_eui.clone(),
                    dev_addr: dev_addr.clone(),
                    dev_public_key: dev_public_key.clone(),
                    edge_s_enc_key: edge_s_enc_key,
                    edge_s_int_key: edge_s_int_key,
                };
                self.active_directory.push(new_dev_info);
            }

            let g_gw_ed: P256SharedSecret<p256::NistP256> = p256::ecdh::diffie_hellman(
                self.private_key.clone().unwrap().to_nonzero_scalar(),
                dev_public_key.as_affine(),
            );
            return g_gw_ed.raw_secret_bytes().to_vec();
        }

        /*
            @brief: This function checks if the device is in the active directory
            @param dev_addr: the dev_addr of the device
            @return: true if the device is in the active directory, false otherwise
        */
        pub fn check_e2ed_enabled(&self, dev_addr: String) -> bool {
            for dev_info in self.active_directory.iter() {
                if dev_info.dev_addr == dev_addr {
                    return true;
                }
            }
            return false;
        }

        pub fn process_frame(
            &self,
            dev_addr: String,
            fcnt: u16,
            phy: EncryptedDataPayload<Vec<u8>, DefaultFactory>,
        ) -> i32 {
            let dev_info: &DevInfo;
            let mut dev_info_found = false;
            for dev_info_iter in self.active_directory.iter() {
                if dev_info_iter.dev_addr == dev_addr {
                    dev_info = dev_info_iter;
                    println!("Dev info {}", dev_info.dev_addr);
                    dev_info_found = true;
                    // GET KEYS
                    let edge_s_enc_key: AES128 = dev_info.edge_s_enc_key.clone();
                    let edge_s_int_key: AES128 = dev_info.edge_s_int_key.clone();
                    let decrypted_data_payload = phy
                        .decrypt(Some(&edge_s_enc_key), Some(&edge_s_int_key), fcnt.into())
                        .unwrap();

                    let frame_payload_result = decrypted_data_payload.frm_payload().unwrap();
                    match frame_payload_result {
                        lorawan_encoding::parser::FRMPayload::Data(frame_payload) => {
                            println!("Edge Frame Payload: {:?}", frame_payload);
                        }
                        _ => println!("Failed to decrypt packet"),
                    };
                    break;
                }
            }
            if dev_info_found {
                return -1;
            }

            return 0;
        }
    }
}

pub static mut E2L_CRYPTO: E2LCrypto = E2LCrypto {
    private_key: None,
    public_key: None,
    compressed_public_key: None,
    active_directory: Vec::new(),
};
