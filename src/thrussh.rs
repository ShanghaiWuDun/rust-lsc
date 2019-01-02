#[macro_use]
extern crate log;
extern crate thrussh;
extern crate thrussh_keys;
extern crate futures;
extern crate tokio;





use futures::Future;
use tokio::net::TcpStream;


pub use thrussh_keys::{ decode_openssh, load_secret_key, load_public_key, decode_secret_key, };
pub use thrussh::client::{ connect_future, Connection, Session, Authenticate, Handler, ChannelOpen, SessionChannel, };


use std::sync::Arc;
use std::net::ToSocketAddrs;



pub struct Client {
    pub config: Arc<thrussh::client::Config>,
    pub identity: Identity,
}


impl thrussh::client::Handler for Client {
    type Error = ();
    type FutureBool = futures::Finished<(Self, bool), Self::Error>;
    type FutureUnit = futures::Finished<Self, Self::Error>;
    type FutureSign = futures::Finished<(Self, thrussh::CryptoVec), Self::Error>;
    type SessionUnit = futures::Finished<(Self, thrussh::client::Session), Self::Error>;

    fn check_server_key(self, server_public_key: &thrussh_keys::key::PublicKey) -> Self::FutureBool {
        trace!("check_server_key: {:?}", server_public_key);
        futures::finished((self, true))
    }

    fn channel_open_confirmation(self, channel: thrussh::ChannelId, session: thrussh::client::Session) -> Self::SessionUnit {
        trace!("channel_open_confirmation: {:?}", channel);
        futures::finished((self, session))
    }

    fn data(self, channel: thrussh::ChannelId, ext: Option<u32>, data: &[u8], session: thrussh::client::Session) -> Self::SessionUnit {
        debug!("data on channel {:?} {:?}: {:?}", ext, channel, std::str::from_utf8(data));
        futures::finished((self, session))
    }
}


#[derive(Debug, Clone)]
pub enum Authentication {
    Passwd(String),
    Key(Arc<thrussh_keys::key::KeyPair>),
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub username: String,
    pub authentication: Authentication,
}



impl Client {
    pub fn new(identity: Identity, config: thrussh::client::Config) -> Result<Self, thrussh::Error> {
        Ok(Self { identity: identity, config: Arc::new(config), })
    }
    
    pub fn send_data<A: ToSocketAddrs>(self, sa: A, msg: &[u8]) -> Result<(), thrussh::Error> {
        let config = self.config.clone();
        let identity = self.identity.clone();

        let username = identity.username;
        let authentication = identity.authentication;

        let msg = msg.to_owned();

        let fut = connect_future(sa, config, None, self, move |connection: Connection<TcpStream, Client>| {
            let conn = match authentication {
                Authentication::Passwd(passwd) => connection.authenticate_password(&username, passwd),
                Authentication::Key(key_pair) => connection.authenticate_key(&username, key_pair),
            };

            conn.and_then(move |session| {
                debug!("session is_authenticated: {:?}", session.is_authenticated());
                session.channel_open_session().and_then(move |(session, channelid)| {
                    session.data(channelid, None, msg).and_then(move |(mut session, _)| {
                        session.disconnect(thrussh::Disconnect::ByApplication, "Ciao", "");
                        session
                        // futures::future::ok(session)
                        // futures::future::ok(())
                    })
                })
            })
        })?;

        tokio::run(fut.map_err(|e| {
            error!("{:?}", e);
            ()
        }));

        Ok(())
    }
}



fn test_thrussh() -> Result<(), thrussh::Error> {
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(5000));

    let identity = Identity {
        username: "ubuntu".to_string(),
        authentication: Authentication::Passwd("Password01!".to_string()),
    };


    let client = Client::new(identity, config)?;
    client.send_data("127.0.0.1:22", "Hi ...".as_bytes())?;

    Ok(())
}

fn test_thrussh2() -> Result<(), thrussh::Error> {
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(5000));

    // With Password:
    // load_secret_key("~/.ssh/id_rsa", Some("password...."))
    let secret_key = match load_secret_key("~/.ssh/id_rsa", None) {
        Ok(skey) => skey,
        Err(e) => {
            error!("{:?}", e);
            return Err(thrussh::Error::CouldNotReadKey);
        }
    };

    let identity = Identity {
        username: "ubuntu".to_string(),
        authentication: Authentication::Key(Arc::new(secret_key)),
    };

    
    let client = Client::new(identity, config)?;
    client.send_data("127.0.0.1:22", "Hi ...".as_bytes())?;

    Ok(())
}