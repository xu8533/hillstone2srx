#!/usr/bin/perl
use warnings;
#use strict;
use Data::Dumper;
use Scalar::Util qw(looks_like_number);
use NetAddr::IP;
use Net::IP::LPM;
use Getopt::Std;
use Cwd 'abs_path';
use File::Basename;
use Excel::Writer::XLSX;
use vars qw($opt_c);
use v5.10.1;
use DateTime::Format::Flexible;
#The major aim of the script is translate juniper's ssg config to juniper srx config

# define variable
my $SRC_ZONE;
my $DST_ZONE;
my @SRC_ADDRESSES;
my @DST_ADDRESSES;
my $POLICY_ACTION;
my $text;
my $GLOBAL_ADDRESS_BOOKS;
my $n=0;
my %hilston_srx_services        = (
    FTP     => "junos-ftp",
    HTTP    => "junos-http",    HTTPS   => "junos-https",
    IKE     => "junos-ike",     IMAP    => "junos-imap",
    LDAP    => "junos-ldap",    MSN     => "junos-msn",
    MAIL    => "junos-mail",    NBDS    => "junos-nbds",
    NBNAME  => "junos-nbname",  NTP     => "junos-ntp",
    PING    => "junos-ping",    POP3    => "junos-pop3",
    PPTP    => "junos-pptp",    RADIUS  => "junos-radius",
    RTSP    => "junos-rtsp",
    RSH     => "junos-rsh",     SIP     => "junos-sip",
    SMTP    => "junos-smtp",    SMB     => "junos-smb",
    SSH     => "junos-ssh",     SYSLOG  => "junos-syslog",
    TFTP    => "junos-tftp",    TELNET  => "junos-telnet",
    WHOIS   => "junos-whois",   WINFRAME    => "junos-winframe",
    'ICMP-ANY'      => "junos-ping",
    'ICMP-any'      => "junos-ping",
    'HTTP-EXT'      => "junos-http-ext",
    'Real-Media'    => "junos-realaudio",
    'Real Media'    => "junos-realaudio",
    'SQL\*Net_V1'   => "junos-sqlnet-v1",
    'SQL\*Net_V2'   => "junos-sqlnet-v2",
    'SQL\*Net V1'   => "junos-sqlnet-v1",
    'SQL\*Net V2'   => "junos-sqlnet-v2",
    'SQL Monitor'   => "junos-sql-monitor",
    'X-WINDOWS'     => "junos-x-windows",
    "H.323"         => "junos-h323",
    'Internet Locator Service'  => "junos-internet-locator-service",
);
my %srx_application_port_number = (
    http    => 80,     https    => 443,     ftp     => 21,
    ssh     => 22,     mail     => 25,      telnet  => 23,
    Terminal => 3389,  SNMP    => "161 to 162",
);

sub set_address_books {
	my $address_book_name = @_;
	for 
}

sub set_services {

}

sub set_polices {

}

#The BEGIN part process some staff
BEGIN {
    if ($#ARGV < 0 || $#ARGV > 5) { die "\nUsage:\tperl hilston2srx.pl <config.file>\n
        Flags:\t-c file for compare between ssg and srx configuration\n"; }
    
    #getopts('c:', \%options); save options to hash %options
	#getopts('c:');  #save options to Getopt::Std side effect sets $opt_*

    if (system("/usr/bin/dos2unix $ARGV[0]") != 0) {
        print "command failed!: dos2unix:\n";
        exit;
    }
    # save all content of config to a variable, we will process the variable instead of <>
    open my $config, '<', $ARGV[0] or die "can't open file:$!\n"; #open the config filehandle
    $text = do { local $/; <$config> };
    close $config;
}

# replace the ssg's predefine services with srx's predefine applications
while (($key, $value) = each %hilston_srx_services) {
    $text =~ s/\b$key\b/$value/gm;
}

my @texts = split(/\n/, $text);
@texts =~ s#\"##g;

for $n++ (@texts) {
    my @configs = split/\s+/;
	given($configs[0]) {
		when ("address") {
			set_address_books ($configs[-1]);		
		}
		when ("service" || "servgroup") {
			set_services ($configs[-1]);
		}
		when ("rule") {
			set_polices ($configs[-1]);
		}
	}
}

# the last jobs
END {
    #replace nat port name with port number
    while (my ($junos_app, $real_port_number) = each %srx_application_port_number) {
        map { s/\b$junos_app\b/$real_port_number/g } @destination_nat;
        map { s/\b$junos_app\b/$real_port_number/g } @source_nat;
    }
    #merge all address books
    local @all_address_books_tmp 
        = (@dst_ip_address_books,
           @global_address_books,
           @mip_address_books
        ); 
    #my @source_nat_rule_set_direction = keys { map { $_ => 1 } @source_nat_zone };
    #my @destination_nat_rule_set_direction = keys { map { $_ => 1 } @destination_nat_zone };
    #remove duplicate source and destination nat rule-set condition 
    my @source_nat_rule_set_direction 
        = do { my %tmp_src;
               grep { !$tmp{$_}++ } @source_nat_zone
             }
        ;
    my @destination_nat_rule_set_direction 
        = do { my %tmp_dst;
               grep { !$tmp{$_}++ } @destination_nat_zone 
             }
        ;
    local @all_address_books 
        = do { my %tmp_all_address_books;
               grep { !$tmp_all_address_books{$_}++ } 
               @all_address_books_tmp
             }
        ;
    @source_nat 
        = grep !/\bdestination-port ping\b/, @source_nat;
    @destination_nat
        = grep !/\bdestination-port ping\b/, @destination_nat;
    foreach (@source_nat) {
        $_ =~ s!\bany\b!0.0.0.0/0!g;
    }
    foreach (@destination_nat) {
        $_ =~ s!\bany\b!0.0.0.0/0!g;
    }
    print @source_nat_rule_set_direction;
    print @source_nat;
    print @destination_nat_rule_set_direction;
    print @destination_nat;
    print @all_address_books;
    print "set applications application traceroute-icmp term t1 protocol icmp\n";
    print "set applications application traceroute-icmp term t1 icmp-type 8\n";
    print "set applications application traceroute-icmp term t1 icmp-code 0\n";
    print "set applications application traceroute-udp term t1 protocol udp\n";
    print "set applications application traceroute-udp term t1 destination-port 33400-34000\n";
    print "set applications application SNMP term 1 protocol udp\n";
    print "set applications application SNMP term 1 destination-port 161-162\n";
    print "set applications application SNMP term 1 inactivity-timeout 30\n";
    print "set applications application SNMP term 2 protocol tcp\n";
    print "set applications application SNMP term 2 destination-port 161-162\n";
    print "set applications application SNMP term 2 inactivity-timeout 30\n";
    print "set applications application DNS term t1 alg dns\n";
    print "set applications application DNS term t1 protocol udp\n";
    print "set applications application DNS term t1 destination-port 53\n";
    print "set applications application DNS term t2 alg dns\n";
    print "set applications application DNS term t2 protocol tcp\n";
    print "set applications application DNS term t2 destination-port 53\n";
    print "set applications application-set TRACEROUTE application traceroute-icmp\n";
    print "set applications application-set TRACEROUTE application traceroute-udp\n";
}
