use std::collections::HashMap;

use self::e2l_crypto::E2LCrypto;
pub(crate) mod e2l_crypto {
    use std::collections::HashMap;
    // Crypto
    extern crate p256;

    use crate::info;
    use p256::elliptic_curve::ecdh::SharedSecret as P256SharedSecret;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::elliptic_curve::PublicKey as P256PublicKey;
    use p256::elliptic_curve::SecretKey as P256SecretKey;

    pub struct DevInfo {
        dev_eui: String,
        dev_addr: String,
        dev_public_key: P256PublicKey<p256::NistP256>,
        edge_s_key: P256SharedSecret<p256::NistP256>,
    }

    #[derive(Default)]
    pub struct E2LCrypto {
        pub private_key: Option<P256SecretKey<p256::NistP256>>,
        pub public_key: Option<P256PublicKey<p256::NistP256>>,
        pub compressed_public_key: Option<Box<[u8]>>,
        pub active_directory: Vec<DevInfo>,
    }

    impl E2LCrypto {
        pub fn handle_ed_pub_info(
            &mut self,
            dev_eui: String,
            dev_addr: String,
            g_as_ed_compressed: Vec<u8>,
            dev_public_key_compressed: Vec<u8>,
        ) -> Vec<u8> {
            info(format!("Received EdPubInfo"));
            let g_as_ed: P256PublicKey<p256::NistP256> =
                P256PublicKey::from_sec1_bytes(&g_as_ed_compressed).unwrap();
            let dev_public_key: P256PublicKey<p256::NistP256> =
                P256PublicKey::from_sec1_bytes(&dev_public_key_compressed).unwrap();

            let edge_s_key: P256SharedSecret<p256::NistP256> = p256::ecdh::diffie_hellman(
                self.private_key.clone().unwrap().to_nonzero_scalar(),
                g_as_ed.as_affine(),
            );
            println!("Secret Key: {:?}", edge_s_key.raw_secret_bytes());
            let dev_info: DevInfo = DevInfo {
                dev_eui: dev_eui.clone(),
                dev_addr: dev_addr.clone(),
                dev_public_key: dev_public_key.clone(),
                edge_s_key: edge_s_key,
            };
            self.active_directory.push(dev_info);

            let g_gw_ed: P256SharedSecret<p256::NistP256> = p256::ecdh::diffie_hellman(
                self.private_key.clone().unwrap().to_nonzero_scalar(),
                dev_public_key.as_affine(),
            );
            return g_gw_ed.raw_secret_bytes().to_vec();
        }

        pub fn generate_ecc_keys(&mut self) -> Box<[u8]> {
            self.private_key = Some(P256SecretKey::random(&mut OsRng));
            self.public_key = Some(self.private_key.clone().unwrap().public_key());
            // Get sec1 bytes of Public Key (TO SEND TO AS)
            self.compressed_public_key = Some(self.public_key.clone().unwrap().to_sec1_bytes());
            return self.compressed_public_key.clone().unwrap();
        }
    }
}

pub static mut E2L_CRYPTO: E2LCrypto = E2LCrypto {
    private_key: None,
    public_key: None,
    compressed_public_key: None,
    active_directory: Vec::new(),
};
