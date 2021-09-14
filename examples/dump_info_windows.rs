use luks2::*;
use std::io::{Read, Seek, SeekFrom};
use windows_drives::BufferedHarddiskVolume;

fn main() {
    let partition_num = 12;
    let partition = BufferedHarddiskVolume::open(partition_num).expect("could not open partition");

    println!("Enter password for partition:");
    let password = password::read().expect("could not read password");

    let sector_size = partition.geometry.bytes_per_sector;
    let mut luks_device =
        LuksDevice::from_device(partition, password.as_bytes(), sector_size as usize)
            .expect("could not create luks device");

    println!("{}", luks_device.header);
    println!("{:#?}", luks_device.json);

    let n = 0x10000;
    let mut sector = vec![0; sector_size as usize];
    luks_device
        .seek(SeekFrom::Start(n))
        .expect("could not seek luks device");
    luks_device
        .read_exact(&mut sector)
        .expect("could not read from luks device");
    println!("{:?}", sector);
}
