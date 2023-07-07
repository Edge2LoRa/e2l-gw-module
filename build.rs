fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/edge2lora_rpc.proto")?;
    Ok(())
}
