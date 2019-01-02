#[macro_use]
extern crate log;
extern crate ssh2;

use ssh2::Session;


use std::io::Read;
use std::net::TcpStream;
use std::net::ToSocketAddrs;


#[derive(Debug)]
pub enum AuthData<'a, 'b> {
    Password(&'a str),
    Pubkey {
        pem_bytes: &'a str,
        key_passwd: Option<&'b str>,
    },
    Agent,
}


pub fn download_rpm_or_deb_packages_over_ssh<SA: ToSocketAddrs>(target: SA, 
                                                                username: &str, 
                                                                authdata: AuthData) -> Result<String, ssh2::Error> {
    let mut sess = Session::new().unwrap();
    let tcp = TcpStream::connect(target).unwrap();
    sess.handshake(&tcp).unwrap();

    match authdata {
        AuthData::Password(passwd) => {
            sess.userauth_password(username, passwd)?;
        },
        AuthData::Pubkey{ pem_bytes, key_passwd } => {
            sess.userauth_pubkey_memory(username, None, pem_bytes, key_passwd)?;
        },
        AuthData::Agent => {
            sess.userauth_agent(username)?;
        },
    }

    if !sess.authenticated() {
        error!("auth failed!");
        return Err(ssh2::Error::new(666, "身份认证信息有误！"));
    }

    let mut channel = sess.channel_session()?;

    if let Ok(_) = channel.exec("dpkg --list") {
        let mut output = String::new();
        let _ = channel.read_to_string(&mut output);
        trace!("$ dpkg --list; exit status: {:?}", channel.exit_status());

        if output.len() > 0 {
            return Ok(output);
        }
    }

    if let Ok(_) = channel.exec("rpm -qa") {
        let mut output = String::new();
        let _ = channel.read_to_string(&mut output);
        trace!("$ rpm -qa; exit status: {:?}", channel.exit_status());
        
        if output.len() > 0 {
            return Ok(output);
        }
    }

    debug!("目标系统无法成功执行 `dpkg --list` 和 `rpm -qa` 命令。");
    let ret = channel.exec("uname -a");
    
    debug!("$ uname -a  --> {:?}", ret);
    let mut output = String::new();
    let _ = channel.read_to_string(&mut output);
    debug!("{:?}", output);

    Err(ssh2::Error::new(999, "Ooops ..."))
}