#!/usr/bin/perl
use warnings;
#use strict;
use Data::Dumper;
use Scalar::Util qw(looks_like_number);
#use NetAddr::IP;
#use Net::IP::LPM;
use Getopt::Std;
use Cwd 'abs_path';
use File::Basename;
#use Excel::Writer::XLSX;
#use vars qw($opt_c);
use v5.10.1;
#use DateTime::Format::Flexible;
#The major aim of the script is translate juniper's ssg config to juniper srx config

# define variable
my $text;   # save all config
my @texts;  # save all config to array
my $n=0;    # line number of config
my %hilston_srx_services        = (
    FTP     => "junos-ftp",     Any     => "any",
    HTTP    => "junos-http",    HTTPS   => "junos-https",
    SSH     => "junos-ssh",     SYSLOG  => "junos-syslog",
    RDP     => "junos-rdp",     ICMP    => "junos-icmp-all",
);

sub set_address_books {
    local $address_book_name = "@_";
    $n++;
    until($texts[$n] eq "exit") {
        local @cells = split/\s+/, $texts[$n];
        given($cells[0]) {
            when ("ip") {
                print "set security address-book global address $address_book_name $cells[-1]\n";
            }
            when ("range") {
                print "set security address-book global address $address_book_name range-address $cells[-2] to $cells[-1]\n";
            }
            when ("description") {
                print "set security address-book global address $address_book_name description $cells[-1]\n";
            }
        }   
        $n++;
    }
    return;
}

sub set_services {
    local ($service_type, $service_name) = @_;  
    $n++;
    if ($service_type eq "service") {
        until ($texts[$n] eq "exit" ) {
            local @cells = split/\s+/, $texts[$n];
            local $cells_num = @cells;
            if ($cells_num == 3) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2] protocol $cells[0] destination-port $cells[2]\n"; 
            }
            elsif ($cells_num == 6) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2] protocol $cells[0] destination-port $cells[2] source-port $cells[-2]-$cells[-1]\n";
            }
            elsif ($cells_num == 7) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2]-$cells[3] protocol $cells[0] destination-port $cells[2]-$cells[3] source-port $cells[-2]-$cells[-1]\n";
            }
            elsif ($cells_num == 4) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2]-$cells[3] protocol $cells[0] destination-port $cells[-2]-$cells[-1]\n"; 
            }
            $n++;
        }
    }
    elsif ($service_type eq "servgroup") {
        until ($texts[$n] eq "exit") {
            local @cells = split/\s+/, $texts[$n];
            print "set applications application-set $service_name application $cells[-1]\n";
            $n++;
        }
    }
    return;
}

sub set_polices {
    local $policy_id = "@_";
    $n++;
    local ($action, $src_zone, $dst_zone, @src_address, @dst_address, @application);
    until($texts[$n] eq "exit") {
        local @cells = split/\s+/, $texts[$n];
        given($cells[0]) {
            when ("action") {
                $action = $cells[-1];   
            }
            when ("src-zone") {
                $src_zone = $cells[-1];
            }
            when ("dst-zone") {
                $dst_zone = $cells[-1];
            }
            when ("src-addr") {
                push @src_address, $cells[-1];
            }
            when ("dst-addr") {
                push @dst_address, $cells[-1];
            }
            when ("src-ip") {
                push @src_address, $cells[-1];
                print "set security address-book global address $cells[-1] $cells[-1]\n";
            }
            when ("dst-ip") {
                push @dst_address, $cells[-1];
                print "set security address-book global address $cells[-1] $cells[-1]\n";
            }
            when ("service") {
                push @application, $cells[-1];
            }
            when ( "src-range") {
                push @src_address, "range-$cells[-2]-$cells[-1]";
                print "set security address-book global address range-$cells[-2]-$cells[-1] range-address $cells[-2] to $cells[-1]\n";
            }
            when ( "dst-range") {
                push @dst_address, "range-$cells[-2]-$cells[-1]";
                print "set security address-book global address range-$cells[-2]-$cells[-1] range-address $cells[-2] to $cells[-1]\n";
            }
        }
        $n++;
    }
    if (defined ($src_zone && $dst_zone) && ($src_zone ne "any" && $dst_zone ne "any")) {
        print "set security policies from-zone $src_zone to-zone $dst_zone policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print "set security policies from-zone $src_zone to-zone $dst_zone policy p_$policy_id then $action\n";
    }
    elsif (defined ($src_zone && $dst_zone) && ($src_zone eq "any" || $dst_zone eq "any")) {
        print "set security policies global policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print "set security policies global policy p_$policy_id match from-zone $src_zone to-zone $dst_zone\n";
        print "set security policies global policy p_$policy_id then $action\n";
    }
    elsif (!defined ($src_zone && $dst_zone)) {
        print "set security policies global policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print "set security policies global policy p_$policy_id then $action\n";
    }
    return;
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
    $text =~ s#\"##g;
    #   $text =~ s/^\s+//g;
    close $config;
}

# replace the ssg's predefine services with srx's predefine applications
while (($key, $value) = each %hilston_srx_services) {
    $text =~ s/\b$key\b/$value/gm;
}

@texts = split(/\n/, $text);

# remove blank lines
@texts = grep { !/(^$|^\n$|^\s+$)/ } @texts;

# remove white at begein and end
@texts = map { s/^\s+|\s+$//gr } @texts;

while ($texts[$n]) {
    my @configs = split/\s+/, $texts[$n];
    given($configs[0]) {
        when ("address") {
            set_address_books ($configs[-1]);       
        }
        when ($_ eq "service" || $_ eq "servgroup") {
            set_services ($configs[0], $configs[-1]);
        }
        when ("rule") {
            set_polices ($configs[-1]);
        }
    }
    $n++;
}

# the last jobs
END {
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
