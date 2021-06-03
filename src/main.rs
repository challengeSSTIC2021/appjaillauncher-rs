extern crate clap;
extern crate env_logger;

//#[macro_use]
extern crate log;

#[cfg(test)]
extern crate kernel32;
extern crate chrono;
extern crate winapi;
extern crate md5; 


include!(concat!(env!("OUT_DIR"), "/version.rs"));

#[cfg(windows)]
mod acl;
mod appcontainer;
mod winffi;
mod asw;
mod privatedirectory;
use std::process;

#[cfg(not(test))]
use asw::HasRawHandle;
use asw::HasRawSocket;

#[cfg(test)]
use winapi::{INVALID_HANDLE_VALUE, DWORD, INFINITE, WAIT_OBJECT_0, HANDLE};

#[cfg(not(test))]
use std::fs;
use std::thread;

#[cfg(test)]
use std::env;
use chrono::{DateTime, Utc};


#[allow(unused_imports)]
use winffi::{GENERIC_WRITE, GENERIC_READ, GENERIC_EXECUTE, GENERIC_ALL};




#[cfg(all(not(test), windows))]
use winapi::HANDLE;
use std::path::{Path, PathBuf};

#[allow(unused_imports)]
use log::*;

#[cfg(not(test))]
use clap::{Arg, App, SubCommand, ArgMatches};

#[cfg(not(test))]
fn build_version() -> String {
    let prebuilt_ver = semver();
    if prebuilt_ver.len() == 0 {
        return format!("build-{} ({})", short_sha(), short_now());
    }

    format!("{}", prebuilt_ver)
}

#[cfg(windows)]
fn add_sid_profile_entry(path: &Path, sid: &str, mask: u32) -> bool {
    // NOTE: Will this mess up for special unicode paths?
    let result = acl::SimpleDacl::from_path(path.to_str().unwrap());
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if dacl.entry_exists(sid, acl::ACCESS_ALLOWED).is_some() {
        if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
            error!("Failed to remove existing ACL entry for AppContainer SID");
            return false;
        }
    }

    if !dacl.add_entry(acl::AccessControlEntry {
                           entryType: acl::ACCESS_ALLOWED,
                           flags: 0,
                           mask: mask,
                           sid: sid.to_string(),
                       }) {
        error!("Failed to add AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path.to_str().unwrap()) {
        Ok(_) => {
            //info!("  Added ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

fn create_profile(
    child_path: &Path,
    is_debug: bool,
    is_outbound: bool,
    profile_name: &str,
) -> appcontainer::Profile {
    // NOTE: Will special unicode paths mess up this unwrap()?
    let profile = match appcontainer::Profile::new(
        profile_name,
        child_path.to_str().unwrap(),
        is_debug,
        is_outbound,
    ) {
        Ok(x) => x,
        Err(x) => {
            error!(
                "Failed to create AppContainer profile for {:}: error={:}",
                profile_name, x
            );
            process::exit(-1);
        }
    };  
    //info!("  profile name = {:}", profile_name);
    //info!("  sid = {:}", profile.sid);
    //info!("  debug = {:}", is_debug);
    //info!("  outbound network = {:}", is_outbound);

    return profile;
}

#[cfg(all(windows, not(test)))]
#[allow(unreachable_code)]
fn do_run(matches: &ArgMatches) {

    let dir_maze = PathBuf::from(matches.value_of("foldermazes").unwrap());

    if let Err(_) = fs::create_dir_all(dir_maze.clone()) {
        println!("Impossible to create tmp directory!");
        process::exit(-1);
    }



    let child_path = Path::new(matches.value_of("CHILD_PATH").unwrap());
    info!("  child_path = {:?}", child_path);

    if !child_path.exists() || child_path.is_dir() || !child_path.is_file() {
        error!("Specified child path ({:?}) is invalid", child_path);
        process::exit(-1);
    }

    let port = matches.value_of("port").unwrap();
    info!("  tcp server port = {:}", port);

    let timeout = matches.value_of("timeout").unwrap().parse::<i64>().unwrap();
    info!("JOB parameters :   timeout before kill = {:}", timeout);

    let nb_process_concurrent = matches.value_of("nb_process_concurrent").unwrap().parse::<u32>().unwrap();
    info!("JOB parameters :  nb processes Concurrent = {:}", nb_process_concurrent);

    let max_memory = matches.value_of("max_memory").unwrap().parse::<u64>().unwrap();
    info!("JOB parameters :  max Memory = {:}", max_memory);


    {
        info!("Attempting to bind to port {:}", port);
        let server = match asw::TcpServer::bind(port) {
            Ok(x) => x,
            Err(x) => {
                error!("Failed to bind server socket on port {:}: GLE={:}", port, x);
                process::exit(-1);
            }
        };

        println!("Listening for clients on port {:}", port);

        let is_debug = matches.is_present("debug");
        let is_outbound = matches.is_present("outbound");

        loop {
            match server.get_event() {
                asw::TcpServerEvent::Accept => {
                    let raw_client = server.accept();
                    if raw_client.is_some() {
                        let (client, addr) = raw_client.unwrap();
                        let addr = addr.clone();
                        let child_path = child_path.to_path_buf();

                        let dir_maze = dir_maze.clone();
                        thread::spawn(move || {
                            handle_client(client, dir_maze, child_path, is_debug, is_outbound, addr, timeout, nb_process_concurrent, max_memory)
                        });
                    }
                }
                _ => {}
            }
        }
        process::exit(0);
    }
}



fn handle_client(
    client: asw::TcpClient,
    dir_maze: PathBuf,
    child_path: PathBuf,
    is_debug: bool,
    is_outbound: bool,
    addr: String,
    timeout: i64,
    nb_process_concurrent: u32,
    max_memory: u64,
) {
    let raw_socket = client.raw_socket();
    let uid = privatedirectory::getUIDUser(raw_socket);
    let raw_socket_handle = client.raw_handle();
    let ip_client: Vec<&str> = addr.as_str().split(":").collect();
    let value_to_hash = format!("{}{}{}", "SSTIC_magic_prefix_dzadza", ip_client[0], uid);
    let digest = md5::compute(value_to_hash.clone());
    let hash_ip_string = format!("{:x}", digest);
    
    let now: DateTime<Utc> = Utc::now();
    println!(
        " + Accepted new client connection from {:} at {}",
        addr,
        now.to_rfc2822()
    );   

    
    let full_profile_name = hash_ip_string.clone();   
    let profile = create_profile(&child_path, is_debug, is_outbound, &full_profile_name);   


    let mut path_mazes_random = dir_maze.clone();    
    path_mazes_random.push(hash_ip_string.clone());
    if let Err(e) = fs::create_dir_all(&path_mazes_random) {
        println!(
            "Impossible to create tmp directory! {:?} {:?}",
            path_mazes_random, e
        );
    }

    if path_mazes_random.to_str().unwrap() != dir_maze.to_str().unwrap() {
        if !add_sid_profile_entry(&path_mazes_random, &profile.sid.clone(), GENERIC_READ | GENERIC_WRITE) {
            error!(
                "Failed to add AppContainer profile ACL entry into {:?}",
                path_mazes_random
            );
            process::exit(-1);
        }

        
        match profile.launch(
            raw_socket_handle as HANDLE,
            raw_socket_handle as HANDLE,
            path_mazes_random.to_str().unwrap(),
            timeout,
            nb_process_concurrent,
            max_memory,
        ) {
            Ok(x) => {
                info!("End of {:}", hash_ip_string);
                unsafe {
                    kernel32::CloseHandle(x.raw);
                };
            }
            Err(_x) => {

                match fs::remove_dir_all(path_mazes_random) {                
                    Ok(_y) => {},
                    Err(e) => eprintln!("Problem while removing dir {}", e),
                  }
                error!("     Failed to launch new process: error={:}", _x);
            }
        }
    }
}



#[cfg(windows)]
fn remove_sid_acl_entry(path: &Path, sid: &str) -> bool {
    // NOTE: Will this mess up for special unicode paths?
    let result = acl::SimpleDacl::from_path(path.to_str().unwrap());
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
        error!("Failed to remove AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path.to_str().unwrap()) {
        Ok(_) => {
            info!("  Removed ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

#[cfg(all(windows, not(test)))]
fn do_clean(matches: &ArgMatches) {
    let profile_name = matches.value_of("name").unwrap();
    println!("Removing AppContainer profile \"{:}\"", profile_name);

    if let Some(raw_key_path) = matches.value_of("key") {
        let key_path = PathBuf::from(raw_key_path);
        let mut key_dir_path = key_path.clone();
        key_dir_path.pop();

        info!("  key_path = {:?}", key_path);
        info!("  key_dir_path = {:?}", key_dir_path);

        if !key_path.exists() || key_path.is_dir() || !key_path.is_file() {
            error!("Specified key path ({:?}) is invalid", key_path);
            process::exit(-1);
        }

        // We create the profile_name with key_path as the child process in order
        // to get the AppContainer SID for profile_name
        let profile = match appcontainer::Profile::new(profile_name, key_path.to_str().unwrap(), false, true) {
            Ok(x) => x,
            Err(x) => {
                error!("Failed to get profile information for \"{:}\": error={:}",
                       profile_name,
                       x);
                process::exit(-1);
            }
        };

        info!("Removing ACL entry for {:} in {:?}", profile.sid, key_path);
        if !remove_sid_acl_entry(&key_path, &profile.sid) {
            error!("Failed to remove entry for key_path={:?}", key_path);
        }

        info!("Removing ACL entry for {:} in {:?}",
              profile.sid,
              key_dir_path);
        if !remove_sid_acl_entry(&key_dir_path, &profile.sid) {
            error!("Failed to remove entry for key_dir_path={:?}", key_dir_path);
        }
    }

    if !appcontainer::Profile::remove(profile_name) {
        error!("  Failed to remove \"{:}\" profile", profile_name);
    } else {
        println!("  SUCCESS - removed \"{:}\" profile", profile_name);
    }

    process::exit(0);
}

#[cfg(all(windows, not(test)))]
fn main() {
    let app_version: &str = &build_version();
    let matches = App::new("AppJailLauncher")
        .version(app_version)
        .author("Andy Ying <andy@trailofbits.com>")
        .about("A TCP server meant for spawning AppContainer'd client processes for Windows-based CTF challenges")
        .subcommand(SubCommand::with_name("run")
            .version(app_version)
            .about("Launch a TCP server")
            .arg(Arg::with_name("name")
                     .short("n")
                     .long("name")
                     .value_name("NAME")
                     .default_value("default_appjail_profile")
                     .help("AppContainer profile name"))
            .arg(Arg::with_name("debug")
                     .long("debug")
                     .help("Enable debug mode where the AppContainers are disabled"))
            .arg(Arg::with_name("outbound")
                     .long("enable-outbound")
                     .help("Enables outbound network connections from the AppContainer'd process"))
            .arg(Arg::with_name("foldermazes")
                     .short("f")
                     .long("foldermazes")
                     .value_name("FOLDER_MAZES")
                     .help("folder mazes"))                     
            .arg(Arg::with_name("port")
                     .short("p")
                     .long("port")
                     .value_name("PORT")
                     .default_value("4577")
                     .help("Port to bind the TCP server on"))
            .arg(Arg::with_name("timeout")
                     .short("t")
                     .long("timeout")
                     .value_name("TIMEOUT")
                     .default_value("120")
                     .help("JOB Limitation : Timeout in seconds after which the program terminates"))             
            .arg(Arg::with_name("nb_process_concurrent")
                     .short("n")
                     .long("nb_process_concurrent")
                     .value_name("nb_process_concurrent")
                     .default_value("10")
                     .help("JOB Limitation : number of process allowed by the job in the jail"))             
            .arg(Arg::with_name("max_memory")
                     .short("m")
                     .long("max_memory")
                     .value_name("max_memory")
                     .default_value("100")
                     .help("JOB Limitation : Amount of RAM allowed to be allocated in MB"))                                  
            .arg(Arg::with_name("CHILD_PATH")
                     .index(1)
                     .required(true)
                     .help("Path to the child process to be AppContainer'd upon TCP client acceptance")))
        .subcommand(SubCommand::with_name("clean")
            .version(app_version)
            .about("Clean AppContainer profiles that have been created on the system")
            .arg(Arg::with_name("name")
                     .short("n")
                     .long("name")
                     .value_name("NAME")
                     .default_value("default_appjail_profile")
                     .help("AppContainer profile name"))
            .arg(Arg::with_name("key")
                     .short("k")
                     .long("key")
                     .value_name("KEYFILE")
                     .help("The path to the \"key\" file that contains the challenge solution token")))
        .get_matches();

    if let Err(_) = env_logger::init() {
        println!("FATAL: failed to initialize env_logger!");
        process::exit(-1);
    }

    if let Some(run_matches) = matches.subcommand_matches("run") {
        info!("Detected subcommand 'run'");
        do_run(run_matches);
    } else if let Some(clean_matches) = matches.subcommand_matches("clean") {
        info!("Detected subcommand 'clean");
        do_clean(clean_matches);
    } else {
        error!("No subcommand provided!");
        process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("Build target is not supported!");
    process::exit(-1);
}

// ----- UNIT TESTS -----
#[cfg(test)]
const KEY_READ_MASK: u32 = 0x00000020;

#[cfg(test)]
fn get_unittest_support_path() -> Option<PathBuf> {
    let mut dir_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => return None,
    };

    while dir_path.pop() {
        dir_path.push("unittest_support");
        if dir_path.exists() && dir_path.is_dir() {
            return Some(dir_path);
        }
        dir_path.pop();
    }

    None
}

#[cfg(test)]
struct ProfileWrapper {
    name: String,
}

#[cfg(test)]
impl Drop for ProfileWrapper {
    fn drop(&mut self) {
        appcontainer::Profile::remove(&self.name);
    }
}

#[cfg(test)]
struct AclOp {
    path: PathBuf,
    sid: String,
}

#[cfg(test)]
impl AclOp {
    fn add(path: &PathBuf, sid: &str, mask: u32) -> Option<AclOp> {
        if !add_sid_profile_entry(&path, sid, mask) {
            return None;
        }

        Some(AclOp {
                 path: PathBuf::from(path),
                 sid: sid.to_string(),
             })
    }
}

#[cfg(test)]
impl Drop for AclOp {
    fn drop(&mut self) {
        remove_sid_acl_entry(&self.path, &self.sid);
    }
}

// This test has some issues
#[allow(unused_variables)]
#[allow(non_snake_case)]
#[ignore]
#[test]
fn test_sandbox_key_read() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let profile_name = String::from("test_default_appjail1");

    let mut child_path = result.unwrap();
    let mut dir_path = child_path.clone();
    child_path.push("sandbox-test.exe");

    dir_path.push("pub");

    let mut key_path = dir_path.clone();
    key_path.push("key2.txt");

    println!("dir_path = {:?}", dir_path);
    println!("key_path = {:?}", key_path);
    println!("Attempting to create AppContainer profile...");

    if let Ok(profile) = appcontainer::Profile::new(&profile_name, child_path.to_str().unwrap(), false, true) {
        let wrapper = ProfileWrapper { name: profile_name };

        println!("Setting ACLs for {:} on {:?}", &profile.sid, dir_path);
        let dirAclOp = AclOp::add(&dir_path, &profile.sid, GENERIC_READ | GENERIC_EXECUTE);
        assert!(dirAclOp.is_some());

        println!("Setting ACLs for {:} on {:?}", &profile.sid, key_path);
        let fileAclOp = AclOp::add(&key_path, &profile.sid, GENERIC_READ);
        assert!(fileAclOp.is_some());

        println!("Testing with default privileges");
        let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                           INVALID_HANDLE_VALUE,
                                           dir_path.to_str().unwrap(),
                                            500 as i64);
        assert!(launch_result.is_ok());

        let hProcess = launch_result.unwrap();
        assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                   WAIT_OBJECT_0);

        let mut dwExitCode: DWORD = 0 as DWORD;
        assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);
        println!("ExitCode = {:08x}", dwExitCode);

        assert!((dwExitCode & KEY_READ_MASK) == 0)
    } else {
        println!("Failed to create AppContainer profile");
        assert!(false);
    }
}



