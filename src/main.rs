#[macro_use]
extern crate error_rules;

use {
    std::{
        io::{
            self,
            BufWriter,
            Write,
        },
        time,
        thread,
        cmp,
        fs::File,
        collections::HashMap,
    },

    epg::{
        Epg,
        EpgError,
    },

    mpegts::{
        ts,
        psi::{
            self,
            PsiDemux,
            Eit,
            EitItem,
            Tdt,
            Tot,
            Desc58,
            Desc58i,
        },
        textcode,
    },

    udp::UdpSocket,

    config::{
        Config,
        Schema,
        ConfigError,
    },

    jiff::{
        Timestamp,
        tz::TimeZone,
    },
};


#[derive(Debug, Error)]
#[error_prefix = "App"]
enum AppError {
    #[error_from]
    Io(io::Error),
    #[error_from]
    Epg(EpgError),
    #[error_from]
    Config(ConfigError),
    #[error_kind("unknown output format")]
    UnknownOutput,
    #[error_kind("output not defined")]
    MissingOutput,
}


type Result<T> = std::result::Result<T, AppError>;


const BLOCK_SIZE: usize = ts::PACKET_SIZE * 7;
const IDLE_DELAY: time::Duration = time::Duration::from_secs(1);


include!(concat!(env!("OUT_DIR"), "/build.rs"));


fn version() {
    println!("eit-stream {} commit:{}", BUILD_DATE, BUILD_ID);
}


fn usage(program: &str) {
    println!(r#"Usage: {} CONFIG

OPTIONS:
    -v, --version       Version information
    -h, --help          Print this text
    -H                  Configuration file format

CONFIG:
    Path to configuration file
"#, program);
}


fn parse_offset(offset: &str) -> i32 {
    offset.parse::<i32>().unwrap_or(0)
}


#[derive(Debug)]
enum Output {
    None,
    Udp(UdpSocket),
    File(BufWriter<File>),
}


impl Default for Output {
    fn default() -> Self {
        Output::None
    }
}


impl Output {
    fn open(addr: &str) -> Result<Self> {
        // TODO: remove collect()
        let dst = addr.splitn(2, "://").collect::<Vec<&str>>();
        match dst[0] {
            "udp" => {
                let s = UdpSocket::open(dst[1])?;
                Ok(Output::Udp(s))
            }
            "file" => {
                let file = File::create(dst[1])?;
                Ok(Output::File(BufWriter::new(file)))
            }
            _ => Err(AppError::UnknownOutput),
        }
    }

    fn send(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Output::Udp(udp) => {
                udp.sendto(data)?;
            }
            Output::File(file) => {
                file.write_all(data)?;
            }
            Output::None => {},
        };
        Ok(())
    }
}


// Helper function to convert offset in seconds to minutes and polarity
fn seconds_to_offset(seconds: i32) -> (u16, u8) {
    let minutes = (seconds.abs() / 60) as u16;
    let polarity = if seconds >= 0 { 0 } else { 1 };
    (minutes, polarity)
}

// Helper function to calculate DST info from timezone at a given point in time
fn calculate_dst_info(tz: &TimeZone, now: Timestamp) -> Result<(u16, u8, u64, u16)> {
    let current_offset = tz.to_offset(now);
    let current_offset_seconds = current_offset.seconds();

    // Find next DST transition using following() iterator
    let (time_of_change, next_offset_seconds) = if let Some(transition) = tz.following(now).next() {
        // Get timestamp and next offset
        let change_ts = transition.timestamp().as_second();
        let next_off = transition.offset().seconds();
        (change_ts as u64, next_off)
    } else {
        // No future transitions
        (0, current_offset_seconds)
    };

    // Convert to minutes and polarity
    let (offset, offset_polarity) = seconds_to_offset(current_offset_seconds);
    let (next_offset, _) = seconds_to_offset(next_offset_seconds);

    Ok((offset, offset_polarity, time_of_change, next_offset))
}


#[derive(Debug)]
struct TdtTot {
    cc: u8,
    tdt: Tdt,
    tot: Tot,
    timezone: Option<TimeZone>,
    output: Option<Output>,
}

impl Default for TdtTot {
    fn default() -> Self {
        Self {
            cc: 0,
            tdt: Tdt::default(),
            tot: Tot::default(),
            timezone: None,
            output: None,
        }
    }
}


impl TdtTot {
    fn parse_config(&mut self, config: &Config) -> Result<()> {
        let country = config.get("country").unwrap_or("   ");

        // Check if both timezone and offset are configured
        let has_timezone = config.get::<&str>("timezone").is_some();
        let has_offset = config.get::<&str>("offset").is_some();

        if has_timezone && has_offset {
            eprintln!("Warning: Both 'timezone' and 'offset' are configured in [tdt-tot] section.");
            eprintln!("         The 'offset' parameter will be ignored. Timezone takes priority.");
        }

        // Try to load timezone first
        let tz_result = if let Some(tz_name) = config.get("timezone") {
            TimeZone::get(tz_name).ok()
        } else {
            None
        };

        let (offset, offset_polarity, time_of_change, next_offset) =
            if let Some(tz) = tz_result {
                // Calculate from timezone data
                self.timezone = Some(tz.clone());
                calculate_dst_info(&tz, Timestamp::now())?
            } else {
                // Fallback to manual offset (backward compatible)
                if !has_timezone {
                    eprintln!("Warning: No timezone configured, using manual offset (DST not supported)");
                }
                let offset = config.get("offset")
                    .map(parse_offset)
                    .unwrap_or(0);

                let (off, pol) = if offset >= 0 {
                    (offset as u16, 0)
                } else {
                    ((-offset) as u16, 1)
                };

                (off, pol, 0, off)  // No DST transition
            };

        if self.tot.descriptors.is_empty() {
            self.tot.descriptors.push(Desc58::default());
        }

        let desc = self.tot.descriptors
            .get_mut(0).unwrap()
            .downcast_mut::<Desc58>();

        desc.items.push(Desc58i {
            country_code: textcode::StringDVB::from_str(country, textcode::ISO6937),
            region_id: 0,
            offset_polarity,
            offset,
            time_of_change,
            next_offset,
        });

        // Parse optional separate output for TDT/TOT
        if let Some(output_addr) = config.get::<&str>("output") {
            self.output = Some(Output::open(output_addr)?);
            eprintln!("TDT/TOT configured with separate output: {}", output_addr);
        }

        Ok(())
    }

    fn update(&mut self) {
        let now = Timestamp::now();
        self.update_at(now);
    }

    fn update_at(&mut self, now: Timestamp) {
        let timestamp = now.as_second() as u64;
        self.tdt.time = timestamp;
        self.tot.time = timestamp;

        // Check if we need to update the descriptor (crossed DST boundary)
        if let Some(tz) = &self.timezone {
            if !self.tot.descriptors.is_empty() {
                let desc = self.tot.descriptors.get(0).unwrap().downcast_ref::<Desc58>();
                if let Some(item) = desc.items.first() {
                    // Check if we've passed the time_of_change
                    if item.time_of_change > 0 && timestamp >= item.time_of_change {
                        // Recalculate DST info
                        if let Ok((new_offset, new_polarity, new_change, new_next)) = calculate_dst_info(tz, now) {
                            // Check if offset actually changed
                            if new_offset != item.offset || new_polarity != item.offset_polarity {
                                // Update the descriptor
                                let desc_mut = self.tot.descriptors.get_mut(0).unwrap().downcast_mut::<Desc58>();
                                if let Some(item_mut) = desc_mut.items.first_mut() {
                                    item_mut.offset = new_offset;
                                    item_mut.offset_polarity = new_polarity;
                                    item_mut.time_of_change = new_change;
                                    item_mut.next_offset = new_next;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn demux(&mut self, dst: &mut Vec<u8>) {
        self.update();
        self.tdt.demux(psi::TDT_PID, &mut self.cc, dst);
        self.tot.demux(psi::TOT_PID, &mut self.cc, dst);
    }
}


#[derive(Default, Debug)]
struct Instance {
    epg_item_id: usize,
    epg_list: Vec<Epg>,
    epg_map: HashMap<String, usize>,

    output: Output,

    multiplex: Multiplex,
    service_list: Vec<Service>,

    onid: u16,
    codepage: u8,
    eit_days: usize,
    eit_rate: Option<usize>,

    utc_offset: i32,
    country: String,

    tdt_tot: Option<TdtTot>,
}


impl Instance {
    fn open_xmltv(&mut self, config: &Config, def: usize) -> Result<Option<usize>> {
        let path = match config.get("xmltv") {
            Some(v) => v,
            None => return Ok(Some(def)),
        };

        if let Some(&v) = self.epg_map.get(path) {
            return Ok(Some(v));
        }

        let mut epg = Epg::default();
        match epg.load(path) {
            Ok(_) => {},
            Err(e) => {
                eprintln!("Error: failed to load XMLTV from {} [{}]", path, e);
                return Ok(None);
            }
        };
        let v = self.epg_list.len();
        self.epg_list.push(epg);
        self.epg_map.insert(path.to_owned(), v);

        Ok(Some(v))
    }

    fn open_output(&mut self, addr: &str) -> Result<()> {
        self.output = Output::open(addr)?;
        Ok(())
    }

    fn parse_config(&mut self, config: &Config) -> Result<()> {
        if ! config.get("enable").unwrap_or(true) {
            return Ok(())
        }

        self.multiplex.onid = config.get("onid")
            .unwrap_or(self.onid);
        self.multiplex.codepage = config.get("codepage")
            .unwrap_or(self.codepage);
        self.multiplex.utc_offset = config.get("utc-offset")
            .map(parse_offset)
            .unwrap_or(self.utc_offset);
        self.multiplex.tsid = config.get("tsid")
            .unwrap_or(1);

        match self.open_xmltv(config, self.epg_item_id)? {
            Some(v) => self.multiplex.epg_item_id = v,
            None => return Ok(()),
        };

        for s in config.iter() {
            if s.get_name() != "service" {
                continue;
            }

            let mut service = Service {
                onid: self.multiplex.onid,
                tsid: self.multiplex.tsid,
                codepage: s.get("codepage")
                    .unwrap_or(self.multiplex.codepage),
                utc_offset: s.get("utc-offset")
                    .map(parse_offset)
                    .unwrap_or(self.multiplex.utc_offset),
                parental_rating: s.get("parental-rating")
                    .unwrap_or(0),
                pnr: s.get("pnr")
                    .unwrap_or(0),

                ..Default::default()
            };

            let xmltv_id = match s.get("xmltv-id") {
                Some(v) => {
                    service.xmltv_id.push_str(v);
                    v
                }
                None => {
                    eprintln!("Warning: 'xmltv-id' option not defined for service at line {}", s.get_line());
                    continue;
                }
            };

            match self.open_xmltv(s, self.multiplex.epg_item_id)? {
                Some(v) => service.epg_item_id = v,
                None => continue,
            };

            if service.epg_item_id == usize::max_value() {
                eprintln!("Error: XMLTV for channel {} is not found", xmltv_id);
                continue;
            }

            self.service_list.push(service);
        }

        Ok(())
    }

    fn parse_tdt_tot(&mut self, config: &Config) -> Result<()> {
        if let Some(t) = &mut self.tdt_tot {
            t.parse_config(config)?;
        } else {
            let mut t = TdtTot::default();
            t.parse_config(config)?;
            self.tdt_tot = Some(t);
        }

        Ok(())
    }
}


#[derive(Default, Debug)]
struct Multiplex {
    epg_item_id: usize,

    onid: u16,
    tsid: u16,
    codepage: u8,
    utc_offset: i32,
}


#[derive(Default, Debug)]
struct Service {
    epg_item_id: usize,

    onid: u16,
    tsid: u16,
    codepage: u8,
    utc_offset: i32,
    parental_rating: u8,

    pnr: u16,
    xmltv_id: String,

    present: Eit,
    schedule: Eit,
}


impl Service {
    fn clear(&mut self) {
        let current_time = chrono::Utc::now().timestamp() as u64;

        if ! self.present.items.is_empty() {
            let event = self.present.items.first().unwrap();
            if event.start + u64::from(event.duration) > current_time {
                return;
            }
            self.present.items.remove(0);
            self.schedule.items.remove(0);

            self.present.version = (self.present.version + 1) % 32;
            self.schedule.version = (self.schedule.version + 1) % 32;
        }

        if self.present.items.is_empty() {
            if let Some(item) = self.schedule.items.get(0) {
                self.present.items.push(item.clone());
            } else {
                return;
            }
        }

        let event = self.present.items.first().unwrap();
        if event.start > current_time {
            return;
        }

        if let Some(item) = self.schedule.items.get(1) {
            self.present.items.push(item.clone());
        }

        let event = self.present.items.first_mut().unwrap();
        event.status = 4;
    }
}


fn init_schema() -> Schema {
    let codepage_validator = |s: &str| -> bool {
        let v = s.parse::<usize>().unwrap_or(1000);
        (v <= 11) || (13 ..= 15).contains(&v) || (v == 21)
    };

    let country_validator = |s: &str| -> bool {
        s.len() == 3
    };

    let offset_validator = |s: &str| -> bool {
        if s.is_empty() { return false }
        match s.as_bytes()[0] {
            b'+' => s[1 ..].parse::<u16>()
                .map(|v| v <= 720)
                .unwrap_or(false),
            b'-' => s[1 ..].parse::<u16>()
                .map(|v| v <= 780)
                .unwrap_or(false),
            b'0' if s.len() == 1 => true,
            _ => false,
        }
    };

    let mut schema_service = Schema::new("service",
        "Service configuration. Multiplex contains one or more services");
    schema_service.set("pnr",
        "Program Number. Required. Should be in range 1 .. 65535",
        true, Schema::range(1 .. 65535));
    schema_service.set("xmltv-id",
        "Program indentifier in the XMLTV. Required",
        true, None);
    schema_service.set("codepage",
        "Redefine codepage for service. Default: multiplex codepage",
        false, codepage_validator);
    schema_service.set("xmltv",
        "Redefine XMLTV source for service. Default: multiplex xmltv",
        false, None);
    schema_service.set("utc-offset",
        "Change UTC time in the range between -720 minutes and +780 minutes. Default: 0",
        false, offset_validator);
    schema_service.set("parental-rating",
        "Recommended minimum age of the end user. Should be in range 4 .. 18. Default: 0",
        false, Schema::range(4 .. 18));

    let mut schema_multiplex = Schema::new("multiplex",
        "Multiplex configuration. App contains one or more multiplexes");
    schema_multiplex.set("tsid",
        "Transport Stream Identifier. Required. Range 0 .. 65535",
        true, Schema::range(0 .. 65535));
    schema_multiplex.set("codepage",
        "Redefine codepage for multiplex. Default: app codepage",
        false, codepage_validator);
    schema_multiplex.set("xmltv",
        "Redefine XMLTV source for multiplex. Default: app xmltv",
        false, None);
    schema_multiplex.set("utc-offset",
        "Change UTC time in the range between -720 minutes and +780 minutes. Default: 0",
        false, offset_validator);
    schema_multiplex.push(schema_service);

    let mut schema_tdt_tot = Schema::new("tdt-tot",
        "Generate TDT/TOT tables");
    schema_tdt_tot.set("country",
        "Country code in ISO 3166-1 alpha-3 format",
        false, country_validator);
    schema_tdt_tot.set("offset",
        "Offset time from UTC in the range between -720 minutes and +780 minutes. Default: 0",
        false, offset_validator);

    let mut schema = Schema::new("",
        "eit-stream - MPEG-TS EPG (Electronic Program Guide) streamer\n\
        #\n\
        # EPG Codepage allowed values:\n\
        #  0 - Default. Latin (ISO 6937)\n\
        #  1 - Western European (ISO 8859-1)\n\
        #  2 - Central European (ISO 8859-2)\n\
        #  3 - South European (ISO 8859-3)\n\
        #  4 - North European (ISO 8859-4)\n\
        #  5 - Cyrillic (ISO 8859-5)\n\
        #  6 - Arabic (ISO 8859-6)\n\
        #  7 - Greek (ISO 8859-7)\n\
        #  8 - Hebrew (ISO 8859-8)\n\
        #  9 - Turkish (ISO 8859-9)\n\
        # 10 - Nordic (ISO 8859-10)\n\
        # 11 - Thai (ISO 8859-11)\n\
        # 13 - Baltic Rim (ISO 8859-13)\n\
        # 14 - Celtic (ISO 8859-14)\n\
        # 15 - Western European (ISO 8859-15)\n\
        # 21 - UTF-8\n\
        #\n\
        # General options:");
    schema.set("xmltv",
        "Full path to XMLTV file or http/https address",
        false, None);
    // TODO: udp address validator
    schema.set("output",
        "UDP Address. Requried. Example: udp://239.255.1.1:10000",
        true, None);
    schema.set("onid",
        "Original Network Identifier. Default: 1",
        false, None);
    schema.set("codepage",
        "EPG Codepage",
        false, codepage_validator);
    schema.set("eit-days",
        "How many days includes into EPG schedule. Range: 1 .. 7. Default: 3",
        false, Schema::range(1 .. 7));
    schema.set("eit-rate",
        "Limit EPG output bitrate in kbit/s. Range: 15 .. 20000. Default: 30 kbit/s per service",
        false, Schema::range(15 .. 20000));
    schema.set("utc-offset",
        "Change UTC time in the range between -720 minutes and +780 minutes. Default: 0",
        false, offset_validator);

    schema.push(schema_tdt_tot);
    schema.push(schema_multiplex);

    schema
}


fn load_config() -> Result<Config> {
    use std::process::exit;

    let mut schema = init_schema();

    let mut args = std::env::args();
    let program = args.next().unwrap();
    let arg = match args.next() {
        Some(v) => match v.as_ref() {
            "-v" | "--version" => {
                version();
                exit(0);
            },
            "-h" | "--help" => {
                usage(&program);
                exit(0);
            },
            "-H" => {
                println!("Configuration file format:\n\n{}", &schema.info());
                exit(0);
            },
            _ => v,
        },
        None => {
            usage(&program);
            exit(0);
        },
    };

    let config = Config::open(&arg)?;
    schema.check(&config)?;

    Ok(config)
}


fn fill_null_ts(dst: &mut Vec<u8>) {
    let remain = dst.len() % BLOCK_SIZE;
    if remain == 0 {
        return;
    }

    let padding = (BLOCK_SIZE - remain) / ts::PACKET_SIZE;
    for _ in 0 .. padding {
        dst.extend_from_slice(ts::NULL_PACKET);
    }
}


fn wrap() -> Result<()> {
    let config = load_config()?;

    let mut instance = Instance {
        onid: config.get("onid").unwrap_or(1),
        codepage: config.get("codepage").unwrap_or(0),
        eit_days: config.get("eit-days").unwrap_or(3),
        eit_rate: config.get("eit-rate"),
        utc_offset: config.get("utc-offset").map(parse_offset).unwrap_or(0),
        country: config.get("country").unwrap_or("   ").to_owned(),
        ..Default::default()
    };

    match instance.open_xmltv(&config, usize::max_value())? {
        Some(v) => instance.epg_item_id = v,
        None => instance.epg_item_id = usize::max_value(),
    };

    match config.get("output") {
        Some(v) => instance.open_output(v)?,
        None => return Err(AppError::MissingOutput),
    };


    for m in config.iter() {
        match m.get_name() {
            "multiplex" => instance.parse_config(m)?,
            "tdt-tot" => instance.parse_tdt_tot(m)?,
            _ => {}
        }
    }

    // Prepare EIT from EPG
    let now = chrono::Utc::now();
    let current_time = now.timestamp() as u64;
    let last_time = (now + chrono::Duration::days(instance.eit_days as i64)).timestamp() as u64;

    for service in &mut instance.service_list {
        let epg = instance.epg_list.get_mut(service.epg_item_id).unwrap();
        let epg_item = match epg.channels.get_mut(&service.xmltv_id) {
            Some(v) => v,
            None => {
                println!("Warning: service \"{}\" not found in XMLTV", &service.xmltv_id);
                continue;
            },
        };

        // Present+Following
        service.present.table_id = 0x4E;
        service.present.pnr = service.pnr;
        service.present.tsid = service.tsid;
        service.present.onid = service.onid;

        // Schedule
        service.schedule.table_id = 0x50;
        service.schedule.pnr = service.pnr;
        service.schedule.tsid = service.tsid;
        service.schedule.onid = service.onid;

        for event in &mut epg_item.events {
            event.start = ((event.start as i64) - (service.utc_offset as i64) * 60) as u64;
            event.stop = ((event.stop as i64) - (service.utc_offset as i64) * 60) as u64;

            if event.start > last_time {
                break;
            }

            if event.stop > current_time {
                event.codepage = service.codepage;

                if service.parental_rating != 0 {
                    let country = instance.country.as_bytes();
                    if country.len() >= 3 {
                        let country_bytes: [u8; 3] = [
                            country[0],
                            country[1],
                            country[2],
                        ];
                        event.parental_rating.insert(
                            country_bytes,
                            service.parental_rating
                        );
                    }
                }

                service.schedule.items.push(EitItem::from(&*event));
            }
        }

        if service.schedule.items.is_empty() {
            println!("Warning: service \"{}\" has empty list", &service.xmltv_id);
        }
    }

    // Main loop

    let mut eit_cc = 0;

    let rate_limit = instance.eit_rate.unwrap_or_else(|| {
        instance.service_list.len() * 30
    });
    let rate_limit = rate_limit * 1000 / 8;
    let pps = time::Duration::from_nanos(
        1_000_000_000u64 * (BLOCK_SIZE as u64) / (rate_limit as u64)
    );


    let mut ts_buffer = Vec::<u8>::with_capacity(
        instance.service_list.len() * ts::PACKET_SIZE * 20
    );

    let mut schedule_skip = 0;

    loop {
        if let Some(tdt_tot) = &mut instance.tdt_tot {
            // Check if TDT/TOT has separate output configured
            let has_separate_output = tdt_tot.output.is_some();

            if has_separate_output {
                // Send TDT/TOT to separate output
                let mut tdt_buffer = Vec::<u8>::with_capacity(ts::PACKET_SIZE * 10);
                tdt_tot.demux(&mut tdt_buffer);
                fill_null_ts(&mut tdt_buffer);

                if !tdt_buffer.is_empty() {
                    if let Some(ref mut tdt_output) = tdt_tot.output {
                        tdt_output.send(&tdt_buffer).unwrap();
                    }
                }
            } else {
                // Send TDT/TOT to main output (default behavior)
                tdt_tot.demux(&mut ts_buffer);
                fill_null_ts(&mut ts_buffer);
            }
        }

        for service in &mut instance.service_list {
            service.clear();

            let mut present_psi_list = service.present.psi_list_assemble();
            if present_psi_list.is_empty() {
                continue;
            }

            for p in &mut present_psi_list {
                p.pid = psi::EIT_PID;
                p.cc = eit_cc;
                p.demux(&mut ts_buffer);
                eit_cc = p.cc;

                fill_null_ts(&mut ts_buffer);
            }
        }

        while schedule_skip < instance.service_list.len() {
            let service = &instance.service_list[schedule_skip];
            schedule_skip += 1;

            let mut schedule_psi_list = service.schedule.psi_list_assemble();
            for p in &mut schedule_psi_list {
                p.pid = psi::EIT_PID;
                p.cc = eit_cc;
                p.demux(&mut ts_buffer);
                eit_cc = p.cc;

                fill_null_ts(&mut ts_buffer);
            }

            if ts_buffer.len() >= rate_limit {
                break;
            }
        }

        if schedule_skip == instance.service_list.len() {
            schedule_skip = 0;
        }

        if ts_buffer.is_empty() {
            thread::sleep(IDLE_DELAY);
            continue;
        }

        let mut skip = 0;
        loop {
            let pkt_len = cmp::min(ts_buffer.len() - skip, BLOCK_SIZE);
            let next = skip + pkt_len;
            instance.output.send(&ts_buffer[skip..next]).unwrap();
            thread::sleep(pps);

            if next < ts_buffer.len() {
                skip = next;
            } else {
                break;
            }
        }

        ts_buffer.clear();
    }
}


fn main() {
    if let Err(e) = wrap() {
        println!("{}", e.to_string());
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Helper: create a TdtTot with a timezone and initial descriptor set at a given time
    fn make_tdt_tot_at(tz_name: &str, country: &str, now: Timestamp) -> TdtTot {
        let tz = TimeZone::get(tz_name).unwrap();
        let (offset, offset_polarity, time_of_change, next_offset) =
            calculate_dst_info(&tz, now).unwrap();

        let mut tdt_tot = TdtTot::default();
        tdt_tot.timezone = Some(tz);
        tdt_tot.tot.descriptors.push(Desc58::default());

        let desc = tdt_tot.tot.descriptors
            .get_mut(0).unwrap()
            .downcast_mut::<Desc58>();

        desc.items.push(Desc58i {
            country_code: textcode::StringDVB::from_str(country, textcode::ISO6937),
            region_id: 0,
            offset_polarity,
            offset,
            time_of_change,
            next_offset,
        });

        tdt_tot
    }

    fn get_desc58i(tdt_tot: &mut TdtTot) -> Desc58i {
        let desc = tdt_tot.tot.descriptors
            .get(0).unwrap()
            .downcast_ref::<Desc58>();
        desc.items.first().unwrap().clone()
    }

    // --- seconds_to_offset ---

    #[test]
    fn seconds_to_offset_positive() {
        // UTC+1 (3600s) → 60 minutes, polarity 0
        let (minutes, polarity) = seconds_to_offset(3600);
        assert_eq!(minutes, 60);
        assert_eq!(polarity, 0);
    }

    #[test]
    fn seconds_to_offset_negative() {
        // UTC-5 (-18000s) → 300 minutes, polarity 1
        let (minutes, polarity) = seconds_to_offset(-18000);
        assert_eq!(minutes, 300);
        assert_eq!(polarity, 1);
    }

    #[test]
    fn seconds_to_offset_zero() {
        let (minutes, polarity) = seconds_to_offset(0);
        assert_eq!(minutes, 0);
        assert_eq!(polarity, 0);
    }

    #[test]
    fn seconds_to_offset_half_hour() {
        // UTC+5:30 (India) = 19800s → 330 minutes
        let (minutes, polarity) = seconds_to_offset(19800);
        assert_eq!(minutes, 330);
        assert_eq!(polarity, 0);
    }

    // --- calculate_dst_info ---

    #[test]
    fn dst_info_warsaw_winter() {
        // 2025-01-15 12:00 UTC — Warsaw is CET (UTC+1), no DST
        let now = Timestamp::from_second(1736942400).unwrap();
        let tz = TimeZone::get("Europe/Warsaw").unwrap();
        let (offset, polarity, time_of_change, next_offset) =
            calculate_dst_info(&tz, now).unwrap();

        assert_eq!(offset, 60);     // CET = UTC+1 = 60 min
        assert_eq!(polarity, 0);    // positive (east)
        assert!(time_of_change > 0); // next DST transition exists
        assert_eq!(next_offset, 120); // CEST = UTC+2 = 120 min
    }

    #[test]
    fn dst_info_warsaw_summer() {
        // 2025-07-15 12:00 UTC — Warsaw is CEST (UTC+2)
        let now = Timestamp::from_second(1752580800).unwrap();
        let tz = TimeZone::get("Europe/Warsaw").unwrap();
        let (offset, polarity, time_of_change, next_offset) =
            calculate_dst_info(&tz, now).unwrap();

        assert_eq!(offset, 120);    // CEST = UTC+2 = 120 min
        assert_eq!(polarity, 0);
        assert!(time_of_change > 0);
        assert_eq!(next_offset, 60); // back to CET
    }

    #[test]
    fn dst_info_new_york_winter() {
        // 2025-01-15 12:00 UTC — New York is EST (UTC-5)
        let now = Timestamp::from_second(1736942400).unwrap();
        let tz = TimeZone::get("America/New_York").unwrap();
        let (offset, polarity, time_of_change, next_offset) =
            calculate_dst_info(&tz, now).unwrap();

        assert_eq!(offset, 300);    // EST = 5 hours = 300 min
        assert_eq!(polarity, 1);    // negative (west)
        assert!(time_of_change > 0);
        assert_eq!(next_offset, 240); // EDT = 4 hours
    }

    #[test]
    fn dst_info_utc_no_transitions() {
        let now = Timestamp::from_second(1736942400).unwrap();
        let tz = TimeZone::get("UTC").unwrap();
        let (offset, polarity, time_of_change, _next_offset) =
            calculate_dst_info(&tz, now).unwrap();

        assert_eq!(offset, 0);
        assert_eq!(polarity, 0);
        assert_eq!(time_of_change, 0); // UTC has no DST transitions
    }

    // --- TdtTot::update_at — timestamp propagation ---

    #[test]
    fn update_at_sets_tdt_tot_time() {
        let now = Timestamp::from_second(1736942400).unwrap();
        let mut tdt_tot = TdtTot::default();
        tdt_tot.update_at(now);

        assert_eq!(tdt_tot.tdt.time, 1736942400);
        assert_eq!(tdt_tot.tot.time, 1736942400);
    }

    // --- TdtTot::update_at — DST boundary crossing ---

    #[test]
    fn update_at_crosses_dst_boundary() {
        // Warsaw: CET→CEST typically last Sunday of March at 01:00 UTC
        // 2025-03-30 01:00 UTC is the spring transition
        // Set up in winter, just before transition
        let before_dst = Timestamp::from_second(1743296400 - 3600).unwrap(); // 1h before transition
        let mut tdt_tot = make_tdt_tot_at("Europe/Warsaw", "POL", before_dst);

        // Verify initial state: CET (UTC+1)
        let item = get_desc58i(&mut tdt_tot);
        assert_eq!(item.offset, 60);
        assert_eq!(item.offset_polarity, 0);
        assert_eq!(item.next_offset, 120); // upcoming CEST

        // Now simulate time passing the DST boundary
        let after_dst = Timestamp::from_second(1743296400 + 60).unwrap(); // 1 min after transition
        tdt_tot.update_at(after_dst);

        // Descriptor should have been updated to CEST (UTC+2)
        let item = get_desc58i(&mut tdt_tot);
        assert_eq!(item.offset, 120);     // now CEST
        assert_eq!(item.offset_polarity, 0);
        assert_eq!(item.next_offset, 60); // next transition back to CET
    }

    #[test]
    fn update_at_no_crossing_keeps_descriptor() {
        // Set up in winter, stay in winter
        let winter = Timestamp::from_second(1736942400).unwrap(); // 2025-01-15
        let mut tdt_tot = make_tdt_tot_at("Europe/Warsaw", "POL", winter);

        let item = get_desc58i(&mut tdt_tot);
        let original_offset = item.offset;
        let original_change = item.time_of_change;

        // Update still in winter — no crossing
        let still_winter = Timestamp::from_second(1736942400 + 86400).unwrap(); // next day
        tdt_tot.update_at(still_winter);

        let item = get_desc58i(&mut tdt_tot);
        assert_eq!(item.offset, original_offset);
        assert_eq!(item.time_of_change, original_change);
    }

    // --- Manual offset (no timezone) ---

    #[test]
    fn manual_offset_no_dst_fields() {
        // Simulate what parse_config does for manual offset (no timezone)
        let mut tdt_tot = TdtTot::default();
        tdt_tot.tot.descriptors.push(Desc58::default());

        let offset: u16 = 300;
        let desc = tdt_tot.tot.descriptors
            .get_mut(0).unwrap()
            .downcast_mut::<Desc58>();

        desc.items.push(Desc58i {
            country_code: textcode::StringDVB::from_str("USA", textcode::ISO6937),
            region_id: 0,
            offset_polarity: 1, // west
            offset,
            time_of_change: 0,
            next_offset: offset,
        });

        let item = get_desc58i(&mut tdt_tot);
        assert_eq!(item.offset, 300);
        assert_eq!(item.offset_polarity, 1);
        assert_eq!(item.time_of_change, 0);
        assert_eq!(item.next_offset, 300); // same as current — no DST
    }
}
