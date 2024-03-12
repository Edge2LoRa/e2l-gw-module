pub(crate) mod e2l_active_directory {
    extern crate p256;
    use p256::elliptic_curve::PublicKey as P256PublicKey;
    use std::collections::HashMap;

    pub struct UnassociatedDevInfo {
        dev_eui: String,
        dev_addr: String,
        e2gw_address: String,
        e2gw_port: u16,
    }

    pub struct AssociatedDevInfo {
        dev_eui: String,
        dev_addr: String,
        dev_public_key: P256PublicKey<p256::NistP256>,
        edge_s_enc_key: AES128,
        edge_s_int_key: AES128,
    }

    pub struct E2LActiveDirectory {
        unassociated_dev_info: HashMap<String, UnassociatedDevInfo>,
        associated_dev_info: HashMap<String, AssociatedDevInfo>,
    }

    impl E2LActiveDirectory {
        pub fn new() -> Self {
            E2LActiveDirectory {
                unassociated_dev_info: HashMap::new(),
                associated_dev_info: HashMap::new(),
            }
        }

        /*
         * @brief: Add unassociated device to the active directory.
         * @param: dev_eui: device EUI.
         * @param: dev_addr: device address.
         * @param: e2gw_address: E2GW address.
         * @param: e2gw_port: E2GW port.
         * @return: None.
         */
        pub fn add_unassociated_dev(
            &mut self,
            dev_eui: String,
            dev_addr: String,
            e2gw_address: String,
            e2gw_port: u16,
        ) {
            self.unassociated_dev_info.insert(
                dev_addr,
                UnassociatedDevInfo {
                    dev_eui,
                    dev_addr,
                    e2gw_address,
                    e2gw_port,
                },
            );
        }

        /*
         * @brief: Add associated device to the active directory.
         * @param: dev_eui: device EUI.
         * @param: dev_addr: device address.
         * @param: dev_public_key: device public key.
         * @param: edge_s_enc_key: edge session encryption key.
         * @param: edge_s_int_key: edge session integrity key.
         */
        pub fn add_associated_dev(
            &mut self,
            dev_eui: String,
            dev_addr: String,
            dev_public_key: P256PublicKey<p256::NistP256>,
            edge_s_enc_key: AES128,
            edge_s_int_key: AES128,
        ) {
            self.associated_dev_info.insert(
                dev_addr,
                AssociatedDevInfo {
                    dev_eui,
                    dev_addr,
                    dev_public_key,
                    edge_s_enc_key,
                    edge_s_int_key,
                },
            );
        }

        /*
         * @brief: Get unassociated device from the active directory.
         * @param: dev_addr: device address.
         * @return: Unassociated device info.
         */
        pub fn get_unassociated_dev(&self, dev_addr: &str) -> Option<&UnassociatedDevInfo> {
            self.unassociated_dev_info.get(dev_addr)
        }

        /*
         * @brief: Get associated device from the active directory.
         * @param: dev_addr: device address.
         * @return: Associated device info.
         */
        pub fn get_associated_dev(&self, dev_addr: &str) -> Option<&AssociatedDevInfo> {
            self.associated_dev_info.get(dev_addr)
        }

        /*
         * @brief: Remove unassociated device from the active directory.
         * @param: dev_addr: device address.
         * @return: None.
         */
        pub fn remove_unassociated_dev(&mut self, dev_addr: &str) {
            self.unassociated_dev_info.remove(dev_addr);
        }

        /*
         * @brief: Remove associated device from the active directory.
         * @param: dev_addr: device address.
         * @return: None.
         */
        pub fn remove_associated_dev(&mut self, dev_addr: &str) {
            self.associated_dev_info.remove(dev_addr);
        }

        /*
         * @brief: Check if the device is associated.
         * @param: dev_addr: device address.
         * @return: True if the device is associated, false otherwise.
         */
        pub fn is_associated_dev(&self, dev_addr: &str) -> bool {
            self.associated_dev_info.contains_key(dev_addr)
        }

        /*
         * @brief: Clear the active directory.
         * #return: None.
         */
        fn clear(&mut self) {
            self.unassociated_dev_info.clear();
            self.associated_dev_info.clear();
        }
    }
}
