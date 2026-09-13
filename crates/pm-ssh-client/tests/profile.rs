// SPDX-License-Identifier: AGPL-3.0-only

use pm_ssh_client::Profile;

const PROFILE: &str = "version=1\nprofile_id=ssh-lab\nintegrations=ssh-server,linux-system-ssh\nmethods=publickey,password\nhost=127.0.0.1\nport=2222\nusername=pmssh\nhost_key_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nconsumer_uid=3\nserver_version=OpenSSH_10.5p1\n";

#[test]
fn installed_profile_is_closed_and_binds_destination_user_hostkey_and_consumer() {
    let profile = Profile::parse(PROFILE.as_bytes()).unwrap();
    assert_eq!(profile.profile_id(), "ssh-lab");
    assert!(profile.allows("ssh-server", "publickey"));
    assert!(profile.allows("linux-system-ssh", "password"));
    assert!(!profile.allows("ssh-server", "keyboard-interactive"));
    assert_eq!(profile.host(), "127.0.0.1");
    assert_eq!(profile.port(), 2222);
    assert_eq!(profile.username(), "pmssh");
    assert_eq!(profile.consumer_uid(), 3);
}

#[test]
fn profile_rejects_unknown_or_ambiguous_transport_configuration() {
    for altered in [
        PROFILE.replace("host=127.0.0.1", "host=bad/host"),
        PROFILE.replace("port=2222", "port=0"),
        PROFILE.replace("username=pmssh", "username=root"),
        PROFILE.replace("server_version=OpenSSH_10.5p1", "server_version=latest"),
        format!("{PROFILE}proxy_command=synthetic\n"),
        PROFILE.replace(
            "integrations=ssh-server,linux-system-ssh",
            "integrations=ssh-server,unknown",
        ),
    ] {
        assert!(Profile::parse(altered.as_bytes()).is_err());
    }
}
